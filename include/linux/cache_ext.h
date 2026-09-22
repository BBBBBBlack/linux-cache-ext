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
// #include <linux/bpf.h>

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

/* Local to the reclaiming memcg, not hierarchical. Page counts use PAGE_SIZE.
 * keep_* reasons are mutually exclusive terminal outcomes per reclaim attempt.
 * Accumulate on the stack and publish once per cache_ext reclaim invocation.
 */
#define CACHE_EXT_RECLAIM_STATS(X) \
  X(calls) \
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
  X(keep_other_pages)

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
};

#define CACHE_EXT_NODE_REMOVED BIT(0)
#define CACHE_EXT_NODE_FREED   BIT(1)

static inline bool cache_ext_list_node_removed(struct cache_ext_list_node* node)
{
  return atomic_read(&node->state) & CACHE_EXT_NODE_REMOVED;
}

static inline bool cache_ext_list_node_freed(struct cache_ext_list_node* node)
{
  return atomic_read(&node->state) & CACHE_EXT_NODE_FREED;
}

static inline void cache_ext_list_node_mark_removed(struct cache_ext_list_node* node)
{
  atomic_or(CACHE_EXT_NODE_REMOVED, &node->state);
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
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup* memcg);

/*
 * Used by the valid_folios_set code
 */
struct cache_ext_list_node* cache_ext_list_node_alloc(struct folio* folio);
void cache_ext_list_node_free(struct cache_ext_list_node* node);
bool cache_ext_list_node_try_pin(struct cache_ext_list_node* node);
void cache_ext_list_node_unpin(struct cache_ext_list_node* node);

/*
 * cache_ext data structure registry.
 */

#define CACHE_EXT_REGISTRY_MAX_ENTRIES 5

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
};

void cache_ext_ds_registry_init(struct cache_ext_ds_registry* registry);
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
