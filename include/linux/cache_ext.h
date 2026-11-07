#ifndef _LINUX_CACHE_EXT_H
#define _LINUX_CACHE_EXT_H 1

/*
 * BPF-Exposed data structures for cache_ext.
 */

#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/srcu.h>
// #include <linux/bpf.h>

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

/* Covers complete ops invocations, including sleeping reclaim, and list
 * helper lookup/use intervals. Never wait for this domain from a reader.
 */
extern struct srcu_struct cache_ext_srcu;
struct cgroup;
void cache_ext_cgroup_detach_begin(struct cgroup *cgrp);

/* Local to the reclaiming memcg, not hierarchical. Counters ending in _pages
 * are page counts in PAGE_SIZE units; calls, *_calls, and *_folios are event or
 * folio counts. keep_* reasons are mutually exclusive terminal outcomes per
 * reclaim attempt. Accumulate on the stack and publish once per cache_ext
 * reclaim invocation.
 */
#define CACHE_EXT_RECLAIM_STATS(X) \
  X(calls) \
  X(requested_pages) \
  X(returned_folios) \
  X(returned_pages) \
  X(short_return_calls) \
  X(zero_return_calls) \
  X(fallback_calls) \
  X(fallback_scan_pages) \
  X(submitted_folios) \
  X(submitted_pages) \
  X(reclaimed_pages) \
  X(keep_lock_pages) \
  X(keep_unevictable_pages) \
  X(keep_unmap_pages) \
  X(keep_reference_activate_pages) \
  X(keep_reference_keep_pages) \
  X(keep_writeback_pages) \
  X(keep_dirty_pages) \
  X(keep_dma_pinned_pages) \
  X(keep_fs_restricted_pages) \
  X(keep_pageout_pages) \
  X(keep_release_pages) \
  X(keep_no_mapping_pages) \
  X(keep_refcount_pages) \
  X(keep_redirtied_pages) \
  X(keep_other_pages) \
  X(deferred_marked_pages) \
  X(deferred_still_dirty_pages) \
  X(deferred_clean_pages) \
  X(deferred_revisit_still_dirty_pages)

enum cache_ext_reclaim_stat_item {
#define CACHE_EXT_RECLAIM_ENUM(name) CACHE_EXT_RECLAIM_##name,
  CACHE_EXT_RECLAIM_STATS(CACHE_EXT_RECLAIM_ENUM)
#undef CACHE_EXT_RECLAIM_ENUM
  CACHE_EXT_RECLAIM_NR_STATS
};

struct cache_ext_reclaim_stats {
  unsigned long count[CACHE_EXT_RECLAIM_NR_STATS];
};

bool cache_ext_is_callback_calling_kfunc_iterate(u32 btf_id);
bool cache_ext_is_callback_calling_kfunc_sample(u32 btf_id);

/******************************************************************************
 * Linked List ****************************************************************
 *****************************************************************************/

/*
 * Indexed Linked List.
 *
 * This is a linked list that is indexed by the folio it contains. This is
 * because we need to be able to quickly:
 * - Find the folio corresponding to a given node.
 * - Find the node corresponding to a given folio.
 *
 * Instead of maintaining a hash-table per list, we can piggyback on the valid
 * folios hashtable we already maintain. It will also keep a pointer to the node
 * in the valid_folio struct.
 */
struct cache_ext_list
{
  struct list_head head;
  // This is for the ds registry.
  struct hlist_node h_node;
  // Reverse pointer to registry for lock access without needing memcg
  struct cache_ext_ds_registry* registry;
  struct mem_cgroup *owner;
  struct hlist_node global_node;
  struct rcu_head retire;
  bool retired;
};

struct cache_ext_list_node
{
  struct folio* folio;

  struct list_head node;

  u64 metadata[2];

  /*
   * Protect nodes temporarily removed from the cache_ext list by sampling.
   * Keep this after BPF-visible fields to avoid changing their offsets.
  */
  atomic_t pin_count;
  atomic_t state;
  struct rcu_head rcu;

  /*
   * Cold path: membership in the per-memcg all_nodes list.  This is separate
   * from node because node is owned by policy lists and may be rebuilt on policy
   * changes, while all_node follows the folio/cache_ext_node lifetime.
   */
  struct list_head all_node;

  /* 0 until metadata and admission are complete. Published with release,
   * consumed with acquire; not a pin or a current-list-membership flag.
   * Appended to preserve existing BPF-visible offsets.
   */
  u64 ready_generation;
};

#define CACHE_EXT_NODE_REMOVED BIT(0)
#define CACHE_EXT_NODE_FREED   BIT(1)
#define CACHE_EXT_NODE_RECLAIM_DEFERRED BIT(2)
#define CACHE_EXT_NODE_RECENT_DEFERRED  BIT(3)
/* Historical successful policy-list admission, NOT current membership.
 * Set under registry->lock and retained until this node is freed.
 */
#define CACHE_EXT_NODE_EVER_ADMITTED BIT(4)
/* Migration owns the binding; ordinary pins and list callbacks must wait. */
#define CACHE_EXT_NODE_MIGRATING BIT(5)
/* Folios added after detach closes publication survive the teardown sweep. */
#define CACHE_EXT_NODE_DETACH_PRESERVE BIT(6)

static inline bool cache_ext_list_node_migrating(struct cache_ext_list_node* node)
{
  return atomic_read(&node->state) & CACHE_EXT_NODE_MIGRATING;
}

static inline bool cache_ext_list_node_removed(struct cache_ext_list_node* node)
{
  return atomic_read(&node->state) & CACHE_EXT_NODE_REMOVED;
}

static inline bool cache_ext_list_node_freed(struct cache_ext_list_node* node)
{
  return atomic_read(&node->state) & CACHE_EXT_NODE_FREED;
}

static inline bool cache_ext_list_node_reclaim_deferred(struct cache_ext_list_node* node)
{
  return atomic_read(&node->state) & CACHE_EXT_NODE_RECLAIM_DEFERRED;
}

static inline bool cache_ext_list_node_recent_deferred(struct cache_ext_list_node* node)
{
  return atomic_read(&node->state) & CACHE_EXT_NODE_RECENT_DEFERRED;
}

static inline void cache_ext_list_node_mark_removed(struct cache_ext_list_node* node)
{
  atomic_or(CACHE_EXT_NODE_REMOVED, &node->state);
  smp_store_release(&node->ready_generation, 0);
}

static inline void cache_ext_list_node_mark_reclaim_deferred(struct cache_ext_list_node* node)
{
  atomic_or(CACHE_EXT_NODE_RECLAIM_DEFERRED, &node->state);
}

static inline void cache_ext_list_node_mark_recent_deferred(struct cache_ext_list_node* node)
{
  atomic_or(CACHE_EXT_NODE_RECENT_DEFERRED, &node->state);
}

static inline void cache_ext_list_node_clear_reclaim_deferred(struct cache_ext_list_node* node)
{
  atomic_andnot(CACHE_EXT_NODE_RECLAIM_DEFERRED, &node->state);
}

static inline void cache_ext_list_node_clear_recent_deferred(struct cache_ext_list_node* node)
{
  atomic_andnot(CACHE_EXT_NODE_RECENT_DEFERRED, &node->state);
}

static inline bool cache_ext_list_node_try_mark_freed(struct cache_ext_list_node* node)
{
  int old = atomic_fetch_or(CACHE_EXT_NODE_FREED, &node->state);

  return !(old & CACHE_EXT_NODE_FREED);
}

/*
 * BPF API
 */

struct sampling_options
{
  __u32 sample_size;
  __u32 select_size;
};

struct cache_ext_sample_opts
{
  __u32 sample_size;
  __u32 reserved;

  u64 sampled_list;
  u64 sampled_mode;

  u64 evict_list;
  u64 evict_mode;

  u64 deferred_list;
  u64 deferred_mode;

  u64 nr_folios_sampled;
  u64 nr_folios_evicted;
  u64 nr_folios_deferred;
  u64 nr_folios_unselectable;
};

int bpf_cache_ext_list_add(u64 list, struct folio* folio);
int bpf_cache_ext_list_add_tail(u64 list, struct folio* folio);
int bpf_cache_ext_list_move(u64 list, struct folio* folio, bool tail);
int bpf_cache_ext_list_del(struct folio* folio);
struct folio* bpf_cache_ext_list_pop(u64 list, bool tail);
int bpf_cache_ext_list_iterate_scan(
    struct mem_cgroup* memcg, u64 list,
    int(iter_fn)(int idx, struct cache_ext_list_node* node));
int bpf_cache_ext_list_iterate(struct mem_cgroup* memcg, u64 list,
                               int(iter_fn)(int idx,
                                            struct cache_ext_list_node* node),
                               struct cache_ext_eviction_ctx* ctx);
int bpf_cache_ext_list_sample(struct mem_cgroup* memcg, u64 list,
                              s64(score_fn)(struct cache_ext_list_node* a),
                              struct sampling_options* opts,
                              struct cache_ext_eviction_ctx* ctx);
int bpf_cache_ext_list_sample_extended(struct mem_cgroup* memcg, u64 list,
                                       s64(score_fn)(struct cache_ext_list_node* a),
                                       struct cache_ext_sample_opts* opts,
                                       struct cache_ext_eviction_ctx* ctx);
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup* memcg);

/*
 * Used by the valid_folios_set code
 */
struct cache_ext_list_node* cache_ext_list_node_alloc(struct folio* folio);
void cache_ext_list_node_free(struct cache_ext_list_node* node);
bool cache_ext_list_node_try_pin(struct cache_ext_list_node* node);
void cache_ext_list_node_unpin(struct cache_ext_list_node* node);

/* Stack-only transaction. The reservation pins the NODE, not the source
 * folio: an extra folio reference would make native migration fail its
 * expected-refcount check. Do not release it with node_unpin().
 */
struct cache_ext_migration {
  struct cache_ext_list_node *node;
  struct cache_ext_ds_registry *registry;
};
int cache_ext_migration_begin(struct folio *src, struct folio *dst,
                             struct cache_ext_migration *migration);
bool cache_ext_migration_mapping_ready(struct folio *src);
void cache_ext_migration_end(struct folio *src, struct folio *dst,
                            struct cache_ext_migration *migration,
                            bool success);

/*
 * cache_ext data structure registry.
 */

#define CACHE_EXT_REGISTRY_MAX_ENTRIES 5

struct cache_ext_ghost_fifo;
void cache_ext_ghost_fifo_retire(struct cache_ext_ghost_fifo *ghost);
int bpf_cache_ext_ghost_fifo_init(struct mem_cgroup *memcg, u32 capacity);
int bpf_cache_ext_ghost_fifo_record(struct folio *folio, u64 generation, u64 key0, u64 key1);
int bpf_cache_ext_ghost_fifo_consume(struct folio *folio, u64 generation, u64 key0, u64 key1);

// NOTE: For now, tie the registry lifetime to the struct_ops lifetime.
// Release all the data structures when the struct_ops is released.
// Do not permit any structure to be released while the struct_ops is
// still in use.
struct cache_ext_ds_registry
{
  DECLARE_HASHTABLE(ds_hash, 5);
  rwlock_t lock;
  int nr_entries;

  struct list_head all_nodes;
  spinlock_t all_nodes_lock;
  atomic64_t nr_nodes;
  /* Nonzero, boot-unique attachment identity; guarded by lock. */
  u64 generation;
  /* Blocks list creation during teardown; new folio nodes are retained. */
  bool closing;
  /* Optional FIFO history, lifetime guarded by RCU, mutations by its own lock. */
  struct cache_ext_ghost_fifo __rcu *ghost_fifo;
};

void cache_ext_ds_registry_init(struct cache_ext_ds_registry* registry);
int cache_ext_ds_registry_begin_generation(struct mem_cgroup* memcg);
void cache_ext_ds_registry_close(struct mem_cgroup* memcg);
unsigned long cache_ext_ds_registry_read_lock(struct folio* folio);
void cache_ext_ds_registry_read_unlock(struct folio* folio, unsigned long flags);
unsigned long cache_ext_ds_registry_write_lock(struct folio* folio);
void cache_ext_ds_registry_write_unlock(struct folio* folio, unsigned long flags);
void cache_ext_ds_registry_del_all(struct mem_cgroup* memcg);
struct cache_ext_list* cache_ext_ds_registry_new_list(struct mem_cgroup* memcg);
struct cache_ext_list*
cache_ext_ds_registry_get(struct cache_ext_ds_registry* registry, u64 list_ptr);
struct cache_ext_ds_registry*
cache_ext_ds_registry_from_folio(struct folio* folio);
struct cache_ext_ds_registry*
cache_ext_ds_registry_from_memcg(struct mem_cgroup* memcg);
#endif // _LINUX_CACHE_EXT_H
