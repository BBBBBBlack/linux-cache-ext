// SPDX-License-Identifier: GPL-2.0
/* Bounded, exact-key FIFO ghost history. One optional store per attachment.
 * Hot path: RCU lifetime guard + one store lock, no allocation or BPF callback.
 * Not a lock-free fast-negative implementation; FIFO ordering is global.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cache_ext.h>
#include <linux/jhash.h>
#include <linux/log2.h>
#include <linux/memcontrol.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "cache_ext_ghost_fifo_core.h"

#define CACHE_EXT_GHOST_MAX_ENTRIES (4U * 1024 * 1024)

struct cache_ext_ghost_fifo {
	struct ce_ghost_fifo q;
	spinlock_t lock;
	u64 generation;
	u32 mask, seed;
	bool dead;
	struct rcu_head rcu;
	struct work_struct free_work;
};

static void cache_ext_ghost_free(struct cache_ext_ghost_fifo *g)
{
	kvfree(g->q.slots);
	kvfree(g->q.buckets);
	kfree(g);
}

static void cache_ext_ghost_free_work(struct work_struct *work)
{
	cache_ext_ghost_free(container_of(work, struct cache_ext_ghost_fifo, free_work));
}

static void cache_ext_ghost_free_rcu(struct rcu_head *rcu)
{
	struct cache_ext_ghost_fifo *g = container_of(rcu, struct cache_ext_ghost_fifo, rcu);

	/* Arrays may be vmalloc-backed: release them in process context. */
	schedule_work(&g->free_work);
}

/* Caller already unpublished the store under registry->lock. */
void cache_ext_ghost_fifo_retire(struct cache_ext_ghost_fifo *g)
{
	unsigned long flags;

	if (!g)
		return;
	spin_lock_irqsave(&g->lock, flags);
	g->dead = true;
	spin_unlock_irqrestore(&g->lock, flags);
	call_rcu(&g->rcu, cache_ext_ghost_free_rcu);
}

__bpf_kfunc int bpf_cache_ext_ghost_fifo_init(struct mem_cgroup *memcg, u32 capacity)
{
	struct cache_ext_ds_registry *registry;
	struct cache_ext_ghost_fifo *g;
	unsigned long flags;
	u64 generation;
	u32 i, buckets;
	int ret = 0;

	if (!memcg || !capacity || capacity > CACHE_EXT_GHOST_MAX_ENTRIES)
		return -EINVAL;
	registry = cache_ext_ds_registry_from_memcg(memcg);
	generation = READ_ONCE(registry->generation);
	if (!generation)
		return -ESTALE;
	g = kzalloc(sizeof(*g), GFP_KERNEL_ACCOUNT);
	if (!g)
		return -ENOMEM;
	buckets = roundup_pow_of_two(capacity);
	g->q.slots = kvcalloc((size_t)capacity + 1, sizeof(*g->q.slots), GFP_KERNEL_ACCOUNT);
	g->q.buckets = kvcalloc(buckets, sizeof(*g->q.buckets), GFP_KERNEL_ACCOUNT);
	if (!g->q.slots || !g->q.buckets) {
		cache_ext_ghost_free(g);
		return -ENOMEM;
	}
	g->q.capacity = capacity;
	g->q.free_head = 1;
	for (i = 1; i < capacity; i++) {
		g->q.slots[i].next = i + 1;
		if (!(i & 4095))
			cond_resched();
	}
	g->mask = buckets - 1;
	g->seed = get_random_u32();
	g->generation = generation;
	spin_lock_init(&g->lock);
	INIT_WORK(&g->free_work, cache_ext_ghost_free_work);
	/* No sleeping allocation under the registry's IRQ-disabled lock. */
	write_lock_irqsave(&registry->lock, flags);
	if (registry->generation != generation)
		ret = -ESTALE;
	else if (rcu_access_pointer(registry->ghost_fifo))
		ret = -EEXIST;
	else
		rcu_assign_pointer(registry->ghost_fifo, g);
	write_unlock_irqrestore(&registry->lock, flags);
	if (ret)
		cache_ext_ghost_free(g);
	return ret;
}

static int cache_ext_ghost_op(struct folio *folio, u64 generation,
			      u64 key0, u64 key1, bool consume)
{
	struct cache_ext_ds_registry *registry;
	struct cache_ext_ghost_fifo *g;
	struct mem_cgroup *memcg;
	unsigned long flags;
	u32 words[4] = { (u32)key0, key0 >> 32, (u32)key1, key1 >> 32 };
	u32 bucket;
	int ret = -ESTALE;

	if (!folio || !generation)
		return -EINVAL;
	rcu_read_lock();
	memcg = folio_memcg(folio);
	if (!memcg)
		goto out;
	/* Match init's per-memcg store, irrespective of the folio's NUMA node. */
	registry = cache_ext_ds_registry_from_memcg(memcg);
	g = rcu_dereference(registry->ghost_fifo);
	if (!g || g->generation != generation)
		goto out;
	bucket = jhash2(words, ARRAY_SIZE(words), g->seed) & g->mask;
	spin_lock_irqsave(&g->lock, flags);
	if (!g->dead) {
		if (consume)
			ret = ce_ghost_consume(&g->q, bucket, key0, key1);
		else {
			ce_ghost_record(&g->q, bucket, key0, key1);
			ret = 0;
		}
	}
	spin_unlock_irqrestore(&g->lock, flags);
out:
	rcu_read_unlock();
	return ret;
}

/* Generic 128-bit key, copied by value; never dereference key0/key1. */
__bpf_kfunc int bpf_cache_ext_ghost_fifo_record(struct folio *folio, u64 generation,
					     u64 key0, u64 key1)
{
	return cache_ext_ghost_op(folio, generation, key0, key1, false);
}

/* 1 = hit consumed, 0 = miss, negative = invalid owner/lifecycle. */
__bpf_kfunc int bpf_cache_ext_ghost_fifo_consume(struct folio *folio, u64 generation,
					      u64 key0, u64 key1)
{
	return cache_ext_ghost_op(folio, generation, key0, key1, true);
}

BTF_SET8_START(cache_ext_ghost_kfunc_ids)
BTF_ID_FLAGS(func, bpf_cache_ext_ghost_fifo_init, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_cache_ext_ghost_fifo_record)
BTF_ID_FLAGS(func, bpf_cache_ext_ghost_fifo_consume)
BTF_SET8_END(cache_ext_ghost_kfunc_ids)

static const struct btf_kfunc_id_set cache_ext_ghost_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &cache_ext_ghost_kfunc_ids,
};

static int __init cache_ext_ghost_register(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &cache_ext_ghost_kfunc_set);
}
__initcall(cache_ext_ghost_register);
