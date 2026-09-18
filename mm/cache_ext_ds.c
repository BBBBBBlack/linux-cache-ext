/*
 * BPF-Exposed data structures for cache_ext.
 */

#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/cache_ext.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/memcontrol.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
/******************************************************************************
 * Linked List ****************************************************************
 *****************************************************************************/

// TODO: In BPF, we need to add the ability to iterate through the linked list.

/*
 * How does BPF add its own data to a data structure node?
 * - Solution 1: Embed the `cache_ext_list_node` in a BPF-defined struct and
 *               use `bpf_obj_new`. The problem is who initializes the
 *				 `cache_ext_list_node`.
 * - Solution 2: Use some page-local storage to store the BPF data.
 * - Solution 3: Use a map from node to data in BPF. This is slower but easier
 *               to start with we will start here.
 */

struct cache_ext_list* cache_ext_list_alloc(void)
{
  /**
   * 重要修改：init逻辑移入SEC("iter/cgroup")
   * 在RCU临界区不允许睡眠
   * GFP_KERNEL 改 GFP_ATOMIC
   */
  // struct cache_ext_list* list =
  //     kmalloc(sizeof(struct cache_ext_list), GFP_KERNEL);
  struct cache_ext_list* list =
      kmalloc(sizeof(struct cache_ext_list), GFP_ATOMIC);
  if (!list)
  {
    return NULL;
  }
  INIT_LIST_HEAD(&list->head);
  return list;
}

struct cache_ext_list_node* cache_ext_list_node_alloc(struct folio* folio)
{
  struct cache_ext_list_node* node =
      kzalloc(sizeof(struct cache_ext_list_node), GFP_NOWAIT);
  if (!node)
  {
    return NULL;
  }
  INIT_LIST_HEAD(&node->node);
  node->folio = folio;
  atomic_set(&node->pin_count, 0);
  node->removed = false;
  return node;
}

void cache_ext_list_node_free(struct cache_ext_list_node* node)
{
  if (!node)
    return;
  if (atomic_read(&node->pin_count) > 0)
  {
    WRITE_ONCE(node->removed, true);
    return;
  }
  kfree(node);
}

bool cache_ext_list_node_try_pin(struct cache_ext_list_node* node)
{
  if (!node || READ_ONCE(node->removed) || !node->folio)
    return false;

  if (!folio_try_get(node->folio))
    return false;

  atomic_inc(&node->pin_count);
  return true;
}

void cache_ext_list_node_unpin(struct cache_ext_list_node* node)
{
  if (!node)
    return;

  if (node->folio)
    folio_put(node->folio);

  if (atomic_dec_and_test(&node->pin_count) && READ_ONCE(node->removed))
    kfree(node);
}

int __cache_ext_list_add_impl(struct cache_ext_list* list, struct folio* folio,
                              bool tail)
{
  unsigned long flags, reg_flags;
  struct valid_folios_set* valid_folios_set = folio_to_valid_folios_set(folio);
  spinlock_t* bucket_lock = valid_folios_set_get_bucket_lock(valid_folios_set, folio);
  spin_lock_irqsave(bucket_lock, flags);
  struct valid_folio* valid_folio = valid_folios_lookup(folio);
  if (!valid_folio)
  {
    spin_unlock_irqrestore(bucket_lock, flags);
    return -1;
  }

  reg_flags = cache_ext_ds_registry_write_lock(folio);

  struct cache_ext_list_node* node = valid_folio->cache_ext_node;
  if (!list_empty(&node->node))
  {
    cache_ext_ds_registry_write_unlock(folio, reg_flags);
    spin_unlock_irqrestore(bucket_lock, flags);
    return -1;
  }

  if (tail)
    list_add_tail(&valid_folio->cache_ext_node->node, &list->head);
  else
    list_add(&valid_folio->cache_ext_node->node, &list->head);

  cache_ext_ds_registry_write_unlock(folio, reg_flags);
  spin_unlock_irqrestore(bucket_lock, flags);
  return 0;
}

int cache_ext_list_add(struct cache_ext_list* list, struct folio* folio)
{
  return __cache_ext_list_add_impl(list, folio, false);
}

int cache_ext_list_add_tail(struct cache_ext_list* list, struct folio* folio)
{
  return __cache_ext_list_add_impl(list, folio, true);
}

int cache_ext_list_move(struct cache_ext_list* list, struct folio* folio,
                        bool tail)
{
  unsigned long flags, reg_flags;
  struct valid_folios_set* valid_folios_set = folio_to_valid_folios_set(folio);
  spinlock_t* bucket_lock = valid_folios_set_get_bucket_lock(valid_folios_set, folio);
  spin_lock_irqsave(bucket_lock, flags);
  struct valid_folio* valid_folio = valid_folios_lookup(folio);
  if (!valid_folio)
  {
    spin_unlock_irqrestore(bucket_lock, flags);
    return -1;
  }

  reg_flags = cache_ext_ds_registry_write_lock(folio);

  if (tail)
    list_move_tail(&valid_folio->cache_ext_node->node, &list->head);
  else
    list_move(&valid_folio->cache_ext_node->node, &list->head);

  cache_ext_ds_registry_write_unlock(folio, reg_flags);
  spin_unlock_irqrestore(bucket_lock, flags);
  return 0;
}

int cache_ext_list_del(struct folio* folio)
{
  unsigned long flags, reg_flags;
  struct valid_folios_set* valid_folios_set = folio_to_valid_folios_set(folio);
  spinlock_t* bucket_lock = valid_folios_set_get_bucket_lock(valid_folios_set, folio);

  spin_lock_irqsave(bucket_lock, flags);

  struct valid_folio* valid_folio = valid_folios_lookup(folio);
  if (!valid_folio)
  {
    spin_unlock_irqrestore(bucket_lock, flags);
    return -ENOENT;
  }

  reg_flags = cache_ext_ds_registry_write_lock(folio);

  if (list_empty(&valid_folio->cache_ext_node->node))
  {
    cache_ext_ds_registry_write_unlock(folio, reg_flags);
    spin_unlock_irqrestore(bucket_lock, flags);
    return -1;
  }

  list_del_init(&valid_folio->cache_ext_node->node);

  cache_ext_ds_registry_write_unlock(folio, reg_flags);
  spin_unlock_irqrestore(bucket_lock, flags);
  return 0;
}

struct folio* cache_ext_list_pop(struct cache_ext_list* list, bool tail)
{
  unsigned long flags;
  struct cache_ext_list_node* node;
  struct folio* folio = NULL;

  if (!list || !list->registry)
    return NULL;

  write_lock_irqsave(&list->registry->lock, flags);
  if (list_empty(&list->head))
  {
    write_unlock_irqrestore(&list->registry->lock, flags);
    return NULL;
  }

  if (tail)
    node = list_last_entry(&list->head, struct cache_ext_list_node, node);
  else
    node = list_first_entry(&list->head, struct cache_ext_list_node, node);

  list_del_init(&node->node);
  folio = node->folio;
  write_unlock_irqrestore(&list->registry->lock, flags);

  return folio;
}

enum cache_ext_iter_callback_ret
{
  CACHE_EXT_CONTINUE_ITER = 0,
  CACHE_EXT_STOP_ITER = 1,
  CACHE_EXT_EVICT_NODE = 2,
};

enum cache_ext_iter_ret
{
  CACHE_EXT_DONE_ITER = 0,
  CACHE_EXT_MAX_ITER_REACHED = 8,
  CACHE_EXT_EVICT_ARRAY_FILLED = 9,
};

static bool cache_ext_evict_ctx_full(struct cache_ext_eviction_ctx* ctx)
{
  if (!ctx)
    return false;

  return ctx->nr_folios_to_evict >= ctx->request_nr_folios_to_evict ||
         ctx->nr_folios_to_evict >= ARRAY_SIZE(ctx->folios_to_evict);
}

int cache_ext_list_iterate(struct mem_cgroup* memcg,
                           struct cache_ext_list* list, void* iter_fn,
                           struct cache_ext_eviction_ctx* ctx)
{
  uint64_t ret = CACHE_EXT_DONE_ITER, cb_ret, iter = 0;
  uint64_t max_iter = 4096;
  struct cache_ext_list_node* node;
  bpf_callback_t bpf_iter_fn = (bpf_callback_t)iter_fn;

  if (cache_ext_evict_ctx_full(ctx))
    return CACHE_EXT_EVICT_ARRAY_FILLED;

  unsigned long flags;
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);
  read_lock_irqsave(&registry->lock, flags);

  list_for_each_entry(node, &list->head, node)
  {
    if (iter > max_iter)
    {
      ret = CACHE_EXT_MAX_ITER_REACHED;
      break;
    }

    // TODO: Ensure that we don't let the callback use any of the list
    // helpers, or we will have a deadlock.
    cb_ret = bpf_iter_fn((u64)iter, (u64)node, (u64)0, (u64)0, (u64)0);
    iter++;

    if (cb_ret == CACHE_EXT_CONTINUE_ITER)
    {
      continue;
    }
    else if (cb_ret == CACHE_EXT_STOP_ITER)
    {
      ret = CACHE_EXT_DONE_ITER;
      break;
    }
    else if (cb_ret == CACHE_EXT_EVICT_NODE)
    {
      if (!ctx)
      {
        pr_warn("cache_ext: Evict requested but ctx is NULL\n");
        ret = -1;
        break;
      }
      ctx->folios_to_evict[ctx->nr_folios_to_evict] = node->folio;
      ctx->nr_folios_to_evict++;

      if (cache_ext_evict_ctx_full(ctx))
      {
        ret = CACHE_EXT_EVICT_ARRAY_FILLED;
        break;
      }
    }
    else
    {
      pr_warn("cache_ext: Unknown iterate return code\n");
      break;
    }
  }

  read_unlock_irqrestore(&registry->lock, flags);
  return ret;
}

enum cache_ext_iterate_mode
{
  CACHE_EXT_ITERATE_SKIP = 0,
  CACHE_EXT_ITERATE_HEAD,
  CACHE_EXT_ITERATE_TAIL,
  CACHE_EXT_ITERATE_MAX,
};

enum cache_ext_iterate_list
{
  CACHE_EXT_ITERATE_SELF = 0,
};

struct cache_ext_iterate_opts
{
  // Options for CACHE_EXT_CONTINUE_ITER nodes
  u64 continue_list;
  u64 continue_mode;

  // Options for CACHE_EXT_EVICT_NODE nodes
  u64 evict_list;
  u64 evict_mode;

  // Output
  u64 nr_folios_continue;
  u64 nr_folios_evict;
};

static bool cache_ext_validate_iterate_opts(struct cache_ext_iterate_opts* opts)
{
  if (opts->continue_mode >= CACHE_EXT_ITERATE_MAX)
    return false;

  if (opts->evict_mode >= CACHE_EXT_ITERATE_MAX)
    return false;

  if (opts->continue_list != CACHE_EXT_ITERATE_SELF &&
      opts->continue_mode == CACHE_EXT_ITERATE_SKIP)
    return false;

  if (opts->evict_list != CACHE_EXT_ITERATE_SELF &&
      opts->evict_mode == CACHE_EXT_ITERATE_SKIP)
    return false;
  return true;
}

int cache_ext_list_iterate_extended(struct mem_cgroup* memcg,
                                    struct cache_ext_list* list, void* iter_fn,
                                    struct cache_ext_iterate_opts* opts,
                                    struct cache_ext_eviction_ctx* ctx)
{
  uint64_t ret = CACHE_EXT_DONE_ITER, cb_ret, iter = 0;
  uint64_t max_iter = 4096;
  struct cache_ext_list_node *node, *node2;
  bpf_callback_t bpf_iter_fn = (bpf_callback_t)iter_fn;
  struct cache_ext_list *continue_list, *evict_list;

  if (!cache_ext_validate_iterate_opts(opts))
    return -1;

  if (cache_ext_evict_ctx_full(ctx))
    return CACHE_EXT_EVICT_ARRAY_FILLED;

  // TODO: pass this from caller
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);

  if (opts->continue_list != CACHE_EXT_ITERATE_SELF)
  {
    continue_list = cache_ext_ds_registry_get(registry, opts->continue_list);
    if (!continue_list)
      return -1;
  }
  else
  {
    continue_list = list;
  }

  if (opts->evict_list != CACHE_EXT_ITERATE_SELF)
  {
    evict_list = cache_ext_ds_registry_get(registry, opts->evict_list);
    if (!evict_list)
      return -1;
  }
  else
  {
    evict_list = list;
  }

  unsigned long flags;
  if (opts->continue_mode == CACHE_EXT_ITERATE_SKIP && opts->evict_mode == CACHE_EXT_ITERATE_SKIP)
    read_lock_irqsave(&registry->lock, flags);
  else
    write_lock_irqsave(&registry->lock, flags);

  list_for_each_entry_safe(node, node2, &list->head, node)
  {
    if (iter > max_iter)
    {
      ret = CACHE_EXT_MAX_ITER_REACHED;
      break;
    }

    // TODO: Ensure that we don't let the callback use any of the list
    // helpers, or we will have a deadlock.
    cb_ret = bpf_iter_fn((u64)iter, (u64)node, (u64)0, (u64)0, (u64)0);
    iter++;

    if (cb_ret == CACHE_EXT_CONTINUE_ITER)
    {
      if (opts->continue_mode == CACHE_EXT_ITERATE_HEAD)
        list_move(&node->node, &continue_list->head);
      else if (opts->continue_mode == CACHE_EXT_ITERATE_TAIL)
        list_move_tail(&node->node, &continue_list->head);

      opts->nr_folios_continue++;

      continue;
    }
    else if (cb_ret == CACHE_EXT_STOP_ITER)
    {
      ret = CACHE_EXT_DONE_ITER;
      break;
    }
    else if (cb_ret == CACHE_EXT_EVICT_NODE)
    {
      ctx->folios_to_evict[ctx->nr_folios_to_evict] = node->folio;
      ctx->nr_folios_to_evict++;

      if (opts->evict_mode == CACHE_EXT_ITERATE_HEAD)
        list_move(&node->node, &evict_list->head);
      else if (opts->evict_mode == CACHE_EXT_ITERATE_TAIL)
        list_move_tail(&node->node, &evict_list->head);

      opts->nr_folios_evict++;

      if (cache_ext_evict_ctx_full(ctx))
      {
        ret = CACHE_EXT_EVICT_ARRAY_FILLED;
        break;
      }
    }
    else
    {
      pr_warn("cache_ext: Unknown iterate return code\n");
      break;
    }
  }

  if (opts->continue_mode == CACHE_EXT_ITERATE_SKIP && opts->evict_mode == CACHE_EXT_ITERATE_SKIP)
    read_unlock_irqrestore(&registry->lock, flags);
  else
    write_unlock_irqrestore(&registry->lock, flags);

  return ret;
}

/*
 * Free the list.
 */
int cache_ext_list_free(struct cache_ext_list* list)
{
  struct cache_ext_list_node *node, *tmp;
  list_for_each_entry_safe(node, tmp, &list->head, node)
  {
    list_del(&node->node);
  }

  kfree(list);
  return 0;
}

// BPF API

__bpf_kfunc int bpf_cache_ext_list_add(u64 list, struct folio* folio)
{
  struct cache_ext_list* list_ptr = cache_ext_ds_registry_get(
      cache_ext_ds_registry_from_folio(folio), list);
  if (!list_ptr)
    return -1;

  return cache_ext_list_add(list_ptr, folio);
};

__bpf_kfunc int bpf_cache_ext_list_add_tail(u64 list, struct folio* folio)
{
  struct cache_ext_list* list_ptr = cache_ext_ds_registry_get(
      cache_ext_ds_registry_from_folio(folio), list);
  if (!list_ptr)
    return -1;

  return cache_ext_list_add_tail(list_ptr, folio);
};

__bpf_kfunc int bpf_cache_ext_list_move(u64 list, struct folio* folio, bool tail)
{
  struct cache_ext_list* list_ptr = cache_ext_ds_registry_get(
      cache_ext_ds_registry_from_folio(folio), list);
  if (!list_ptr)
    return -1;

  return cache_ext_list_move(list_ptr, folio, tail);
};

__bpf_kfunc int bpf_cache_ext_list_del(struct folio* folio)
{
  return cache_ext_list_del(folio);
};

__bpf_kfunc struct folio* bpf_cache_ext_list_pop(u64 list, bool tail)
{
  struct cache_ext_list* list_ptr = (struct cache_ext_list*)list;
  if (!list_ptr || !list_ptr->registry)
    return NULL;

  return cache_ext_list_pop(list_ptr, tail);
};

__bpf_kfunc int bpf_cache_ext_list_iterate(
    struct mem_cgroup* memcg, u64 list,
    int(iter_fn)(int idx, struct cache_ext_list_node* node),
    struct cache_ext_eviction_ctx* ctx)
{
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);
  struct cache_ext_list* list_ptr = cache_ext_ds_registry_get(registry, list);
  if (!list_ptr)
    return -1;

  return cache_ext_list_iterate(memcg, list_ptr, (void*)iter_fn, ctx);
};

__bpf_kfunc int bpf_cache_ext_list_iterate_scan(
    struct mem_cgroup* memcg, u64 list,
    int(iter_fn)(int idx, struct cache_ext_list_node* node))
{
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);
  struct cache_ext_list* list_ptr = cache_ext_ds_registry_get(registry, list);
  if (!list_ptr)
    return -1;

  return cache_ext_list_iterate(memcg, list_ptr, (void*)iter_fn, NULL);
};

__bpf_kfunc int bpf_cache_ext_list_iterate_extended(
    struct mem_cgroup* memcg, u64 list,
    int(iter_fn)(int idx, struct cache_ext_list_node* node),
    struct cache_ext_iterate_opts* opts,
    struct cache_ext_eviction_ctx* ctx)
{
  if (!opts)
    return -1;

  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);
  struct cache_ext_list* list_ptr = cache_ext_ds_registry_get(registry, list);
  if (!list_ptr)
    return -1;

  return cache_ext_list_iterate_extended(memcg, list_ptr, (void*)iter_fn, opts, ctx);
};

#define MAX_SAMPLE_FOLIOS 2048
DEFINE_PER_CPU(struct cache_ext_list_node*, sample_folios[MAX_SAMPLE_FOLIOS]);

void __putback_list_nodes(struct cache_ext_list* list, struct cache_ext_list_node** sample_folios_arr, int size)
{
  for (int i = 0; i < size; i++)
  {
    struct cache_ext_list_node* node = sample_folios_arr[i];
    if (!node)
      continue;

    if (READ_ONCE(node->removed))
      continue;

    // HACK: Check if either left or right pointer is poisoned
    if (node->node.next == LIST_POISON1 ||
        node->node.next == LIST_POISON2 ||
        node->node.prev == LIST_POISON1 ||
        node->node.prev == LIST_POISON2)
    {
      pr_warn("cache_ext: folio removed from page cache while isolated by sampling\n");
      WRITE_ONCE(node->removed, true);
      continue;
    }

    if (list_empty(&node->node))
      list_add_tail(&node->node, &list->head);
  }
}

void __unpin_sample_nodes(struct cache_ext_list_node** sample_folios_arr, int size)
{
  for (int i = 0; i < size; i++)
  {
    if (!sample_folios_arr[i])
      continue;
    cache_ext_list_node_unpin(sample_folios_arr[i]);
    sample_folios_arr[i] = NULL;
  }
}

int __bpf_cache_ext_list_sample(struct mem_cgroup* memcg, u64 list,
                                s64(score_fn)(struct cache_ext_list_node* a),
                                struct sampling_options* opts,
                                struct cache_ext_eviction_ctx* ctx)
{
  // Select the first select_size elements with the lowest score out of
  // sample_size elements in the given list.
  int sample_size = opts->sample_size;
  int num_folios_to_sample = ctx->request_nr_folios_to_evict * sample_size;
  if (num_folios_to_sample > MAX_SAMPLE_FOLIOS)
  {
    pr_warn("cache_ext: num_folios_to_sample is too large\n");
    return -1;
  }
  int sample_folios_size = 0;
  struct cache_ext_list_node** sample_folios_arr = this_cpu_ptr(sample_folios);

  unsigned long flags;
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);
  struct cache_ext_list* list_ptr = cache_ext_ds_registry_get(registry, list);
  if (!list_ptr)
  {
    pr_err("cache_ext: list is NULL\n");
    return -1;
  }
  write_lock_irqsave(&registry->lock, flags);

  // Optimization: Snip the front of the list and select the pages without
  // holding the lock.
  for (int attempts = 0; sample_folios_size < num_folios_to_sample &&
                       attempts < num_folios_to_sample * 2; attempts++)
  {
    if (list_empty(&list_ptr->head))
    {
      pr_warn("cache_ext: ran out of folios to sample\n");
      __putback_list_nodes(list_ptr, sample_folios_arr, sample_folios_size);
      write_unlock_irqrestore(&registry->lock, flags);
      __unpin_sample_nodes(sample_folios_arr, sample_folios_size);
      return -1;
    }
    struct cache_ext_list_node* node = list_first_entry(
        &list_ptr->head, struct cache_ext_list_node, node);
    if (!cache_ext_list_node_try_pin(node))
    {
      list_move_tail(&node->node, &list_ptr->head);
      continue;
    }
    sample_folios_arr[sample_folios_size] = node;
    sample_folios_size++;
    // if (node->node.next == NULL || node->node.prev == NULL) {
    // 	pr_warn("cache_ext: node->node.next or node->node.prev is NULL\n");
    // }
    list_del_init(&node->node);
  }

  write_unlock_irqrestore(&registry->lock, flags);

  // 1. For every n elements, evict the one with the min score
  ctx->nr_folios_to_evict = 0;
  int sample_folios_idx = 0;
  int nr_selectable = sample_folios_size / sample_size;
  if (nr_selectable > ctx->request_nr_folios_to_evict)
    nr_selectable = ctx->request_nr_folios_to_evict;
  for (int i = 0; i < nr_selectable; i++)
  {
    struct cache_ext_list_node* min_node = sample_folios_arr[sample_folios_idx];
    s64 min_score = READ_ONCE(min_node->removed) ? S64_MAX : score_fn(min_node);

    sample_folios_idx++;

    // if (!min_node) {
    // 	pr_warn("cache_ext: min_node is NULL, ran out of folios to evict\n");
    // 	break;
    // }

    for (int j = 1; j < sample_size; j++)
    {
      struct cache_ext_list_node* curr_node = sample_folios_arr[sample_folios_idx];
      s64 curr_score = READ_ONCE(curr_node->removed) ? S64_MAX : score_fn(curr_node);
      sample_folios_idx++;
      if (curr_score < min_score)
      {
        min_score = curr_score;
        min_node = curr_node;
      }
    }
    if (!READ_ONCE(min_node->removed) && min_score != S64_MAX)
    {
      if (cache_ext_list_node_try_pin(min_node))
      {
        ctx->folios_to_evict[ctx->nr_folios_to_evict] = min_node->folio;
        ctx->scores[ctx->nr_folios_to_evict] = min_score;
        ctx->nodes_to_evict[ctx->nr_folios_to_evict] = min_node;
        ctx->nr_folios_to_evict++;
      }
    }
  }

  // 2. Put everything to the back of the list.
  write_lock_irqsave(&registry->lock, flags);
  __putback_list_nodes(list_ptr, sample_folios_arr, sample_folios_size);
  write_unlock_irqrestore(&registry->lock, flags);
  __unpin_sample_nodes(sample_folios_arr, sample_folios_size);

  return 0;
}

__bpf_kfunc int
bpf_cache_ext_list_sample(struct mem_cgroup* memcg, u64 list,
                          s64(score_fn)(struct cache_ext_list_node* a),
                          struct sampling_options* opts,
                          struct cache_ext_eviction_ctx* ctx)
{
  scoped_guard(preempt)
  {
    return __bpf_cache_ext_list_sample(memcg, list, score_fn, opts, ctx);
  }
  BUG();
}

enum cache_ext_list_ops_type
{
  KF_bpf_cache_ext_list_add,
  KF_bpf_cache_ext_list_add_tail,
  KF_bpf_cache_ext_list_del,
  KF_bpf_cache_ext_list_pop,
  KF_bpf_cache_ext_list_iterate_readonly,
  KF_bpf_cache_ext_list_iterate,
  KF_bpf_cache_ext_list_sample,
  KF_bpf_cache_ext_list_move,
  KF_bpf_cache_ext_list_iterate_extended,
};

BTF_SET8_START(cache_ext_list_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add_tail)
BTF_ID_FLAGS(func, bpf_cache_ext_list_del)
BTF_ID_FLAGS(func, bpf_cache_ext_list_pop, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_list_iterate_scan)
BTF_ID_FLAGS(func, bpf_cache_ext_list_iterate)
BTF_ID_FLAGS(func, bpf_cache_ext_list_sample)
BTF_ID_FLAGS(func, bpf_cache_ext_list_move)
BTF_ID_FLAGS(func, bpf_cache_ext_list_iterate_extended)
BTF_SET8_END(cache_ext_list_ops)

BTF_ID_LIST(cache_ext_list_ops_list)
BTF_ID(func, bpf_cache_ext_list_add)
BTF_ID(func, bpf_cache_ext_list_add_tail)
BTF_ID(func, bpf_cache_ext_list_del)
BTF_ID(func, bpf_cache_ext_list_pop)
BTF_ID(func, bpf_cache_ext_list_iterate_scan)
BTF_ID(func, bpf_cache_ext_list_iterate)
BTF_ID(func, bpf_cache_ext_list_sample)
BTF_ID(func, bpf_cache_ext_list_move)
BTF_ID(func, bpf_cache_ext_list_iterate_extended)

noinline bool cache_ext_is_callback_calling_kfunc_iterate(u32 btf_id)
{
  return (btf_id == cache_ext_list_ops_list[KF_bpf_cache_ext_list_iterate_readonly] ||
          btf_id == cache_ext_list_ops_list[KF_bpf_cache_ext_list_iterate] ||
          btf_id == cache_ext_list_ops_list[KF_bpf_cache_ext_list_iterate_extended]);
}

noinline bool cache_ext_is_callback_calling_kfunc_sample(u32 btf_id)
{
  return (btf_id == cache_ext_list_ops_list[KF_bpf_cache_ext_list_sample]);
}

static const struct btf_kfunc_id_set cache_ext_kfunc_set_list_ops = {
    .owner = THIS_MODULE,
    .set = &cache_ext_list_ops,
};

/******************************************************************************
 * DS Registry ****************************************************************
 *****************************************************************************/

void cache_ext_ds_registry_init(struct cache_ext_ds_registry* registry)
{
  hash_init(registry->ds_hash);
  rwlock_init(&registry->lock);
  registry->nr_entries = 0;
}

struct cache_ext_ds_registry*
cache_ext_ds_registry_from_memcg(struct mem_cgroup* memcg)
{
  return &memcg->nodeinfo[0]->cache_ext_ds_registry;
}

struct cache_ext_list* cache_ext_ds_registry_new_list(struct mem_cgroup* memcg)
{
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);
  struct cache_ext_list* list = cache_ext_list_alloc();
  if (list == NULL)
  {
    return NULL;
  }
  unsigned long flags;
  write_lock_irqsave(&registry->lock, flags);
  if (registry->nr_entries >= CACHE_EXT_REGISTRY_MAX_ENTRIES)
  {
    write_unlock_irqrestore(&registry->lock, flags);
    cache_ext_list_free(list);
    return NULL;
  }
  list->registry = registry;
  u64 key = (u64)list;
  hash_add(registry->ds_hash, &list->h_node, key);
  registry->nr_entries++;
  write_unlock_irqrestore(&registry->lock, flags);

  return list;
}

struct cache_ext_list*
cache_ext_ds_registry_get(struct cache_ext_ds_registry* registry, u64 list_ptr)
{
  unsigned long flags;
  struct cache_ext_list* cur_list;
  u64 key = list_ptr;
  read_lock_irqsave(&registry->lock, flags);
  hash_for_each_possible(registry->ds_hash, cur_list, h_node, key)
  {
    if (key == (u64)cur_list)
    {
      read_unlock_irqrestore(&registry->lock, flags);
      return cur_list;
    }
  }
  read_unlock_irqrestore(&registry->lock, flags);

  return NULL;
}

struct cache_ext_ds_registry*
cache_ext_ds_registry_from_folio(struct folio* folio)
{
  // Get cgroup from folio
  struct mem_cgroup* memcg = folio_memcg(folio);
  // Get pgdat from folio
  pg_data_t* pgdat = folio_pgdat(folio);
  // Get node cgroup
  struct mem_cgroup_per_node* node_cgroup = memcg->nodeinfo[pgdat->node_id];
  // Get valid folios set from cgroup
  return &node_cgroup->cache_ext_ds_registry;
}

struct cache_ext_ds_registry*
cache_ext_ds_registry_from_mem_cgroup(struct mem_cgroup* memcg)
{
  return &memcg->nodeinfo[0]->cache_ext_ds_registry;
}

unsigned long cache_ext_ds_registry_read_lock(struct folio* folio)
{
  unsigned long flags;
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_folio(folio);
  read_lock_irqsave(&registry->lock, flags);
  return flags;
}

void cache_ext_ds_registry_read_unlock(struct folio* folio, unsigned long flags)
{
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_folio(folio);
  read_unlock_irqrestore(&registry->lock, flags);
}

unsigned long cache_ext_ds_registry_write_lock(struct folio* folio)
{
  unsigned long flags;
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_folio(folio);
  write_lock_irqsave(&registry->lock, flags);
  return flags;
}

void cache_ext_ds_registry_write_unlock(struct folio* folio, unsigned long flags)
{
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_folio(folio);
  write_unlock_irqrestore(&registry->lock, flags);
}

void cache_ext_ds_registry_del_all(struct mem_cgroup* memcg)
{
  unsigned long flags;
  int bkt;
  struct hlist_node* tmp;
  struct cache_ext_list* cur_list;
  struct cache_ext_ds_registry* registry = cache_ext_ds_registry_from_memcg(memcg);
  write_lock_irqsave(&registry->lock, flags);
  hash_for_each_safe(registry->ds_hash, bkt, tmp, cur_list, h_node)
  {
    hash_del(&cur_list->h_node);
    cache_ext_list_free(cur_list);
  }
  registry->nr_entries = 0;
  write_unlock_irqrestore(&registry->lock, flags);
  struct valid_folios_set* valid_folios_set = memcg_to_valid_folios_set(memcg);
  valid_folios_clear_list(valid_folios_set);
}

// BPF API

__bpf_kfunc u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup* memcg)
{
  return (u64)cache_ext_ds_registry_new_list(memcg);
}

__bpf_kfunc u64 bpf_cache_ext_ds_registry_new_list_from_folio(struct folio* folio)
{
  struct mem_cgroup* memcg = folio_memcg(folio);
  if (!memcg)
    return 0;
  return (u64)cache_ext_ds_registry_new_list(memcg);
}

BTF_SET8_START(cache_ext_registry_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_ds_registry_new_list)
BTF_ID_FLAGS(func, bpf_cache_ext_ds_registry_new_list_from_folio)
BTF_SET8_END(cache_ext_registry_ops)

static const struct btf_kfunc_id_set cache_ext_kfunc_set_registry_ops = {
    .owner = THIS_MODULE,
    .set = &cache_ext_registry_ops,
};

__bpf_kfunc u64 bpf_cache_ext_folio_to_handle(struct folio* folio, u64 secret_key)
{
  if (!folio)
    return 0;
  return (u64)folio ^ secret_key;
}

__bpf_kfunc u64 bpf_cache_ext_memcg_to_handle(struct mem_cgroup* memcg, u64 secret_key)
{
  if (!memcg)
    return 0;
  return (u64)memcg ^ secret_key;
}

__bpf_kfunc u64 bpf_cache_ext_ctx_to_handle(struct cache_ext_eviction_ctx* ctx, u64 secret_key)
{
  if (!ctx)
    return 0;
  return (u64)ctx ^ secret_key;
}

__bpf_kfunc struct folio* bpf_cache_ext_handle_to_folio(u64 handle, u64 secret_key)
{
  // unsigned long addr = (unsigned long)(handle ^ secret_key);
  // struct folio* f = (struct folio*)addr;
  // if (addr & (PAGE_SIZE - 1))
  //   return NULL;
  // if (!virt_addr_valid(f))
  //   return NULL;
  // return f;
  return (struct folio*)(handle ^ secret_key);
}

__bpf_kfunc struct mem_cgroup* bpf_cache_ext_handle_to_memcg(u64 handle, u64 secret_key)
{
  return (struct mem_cgroup*)(handle ^ secret_key);
}

__bpf_kfunc struct cache_ext_eviction_ctx* bpf_cache_ext_handle_to_ctx(u64 handle, u64 secret_key)
{
  return (struct cache_ext_eviction_ctx*)(handle ^ secret_key);
}

__bpf_kfunc u64 bpf_cache_ext_evicted_ctx_to_handle(struct cache_ext_evicted_ctx* ctx, u64 secret_key)
{
  if (!ctx)
    return 0;
  return (u64)ctx ^ secret_key;
}

__bpf_kfunc struct cache_ext_evicted_ctx* bpf_cache_ext_handle_to_evicted_ctx(u64 handle, u64 secret_key)
{
  return (struct cache_ext_evicted_ctx*)(handle ^ secret_key);
}

__bpf_kfunc struct mem_cgroup* bpf_cgroup_to_memcg(struct cgroup* cgrp)
{
#ifdef CONFIG_MEMCG
  if (!cgrp)
    return NULL;

  struct cgroup_subsys_state* css;

  // cgroup_get_e_css 获取指定子系统的 css
  // &memory_cgrp_subsys: 内存子系统的描述符
  css = cgroup_get_e_css(cgrp, &memory_cgrp_subsys);

  if (!css)
    return NULL;

  return mem_cgroup_from_css(css);
#else
  return NULL;
#endif
}

__bpf_kfunc struct mem_cgroup* bpf_cache_ext_folio_to_memcg(struct folio* folio)
{
  if (!folio)
    return NULL;
  return folio_memcg(folio);
}

__bpf_kfunc struct cache_ext_list_node* bpf_cache_ext_folio_to_node(struct folio* folio)
{
  if (!folio)
    return NULL;

  struct valid_folios_set* vfs = folio_to_valid_folios_set(folio);
  if (!vfs)
    return NULL;

  spinlock_t* bucket_lock = valid_folios_set_get_bucket_lock(vfs, folio);
  unsigned long flags;
  spin_lock_irqsave(bucket_lock, flags);

  struct valid_folio* vf = valid_folios_lookup(folio);
  struct cache_ext_list_node* node = vf ? vf->cache_ext_node : NULL;

  spin_unlock_irqrestore(bucket_lock, flags);
  return node;
}

static inline void metadata_copy(u64* dst, const void* src, u32 sz)
{
  const u64* s = src;
  if (sz >= 16) {
    dst[0] = s[0];
    dst[1] = s[1];
  } else if (sz >= 8) {
    dst[0] = s[0];
  }
}

__bpf_kfunc int bpf_cache_ext_folio_set_metadata(struct folio* folio,
                                                  void* data, u32 data__sz)
{
  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node || data__sz > sizeof(node->metadata))
    return -EINVAL;
  metadata_copy(node->metadata, data, data__sz);
  return 0;
}

__bpf_kfunc u64 bpf_cache_ext_folio_add_metadata(struct folio* folio, u32 idx,
                                                  u64 val)
{
  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node || idx > 1)
    return 0;
  return __sync_fetch_and_add(&node->metadata[idx], val);
}

__bpf_kfunc int bpf_cache_ext_node_set_metadata(
    struct cache_ext_list_node* node, void* data, u32 data__sz)
{
  if (!node || data__sz > sizeof(node->metadata))
    return -EINVAL;
  metadata_copy(node->metadata, data, data__sz);
  return 0;
}

__bpf_kfunc u64 bpf_cache_ext_node_add_metadata(
    struct cache_ext_list_node* node, u32 idx, u64 val)
{
  if (!node || idx > 1)
    return 0;
  return __sync_fetch_and_add(&node->metadata[idx], val);
}

BTF_SET8_START(cache_ext_handle_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_folio_to_handle)
BTF_ID_FLAGS(func, bpf_cache_ext_memcg_to_handle)
BTF_ID_FLAGS(func, bpf_cache_ext_ctx_to_handle)
BTF_ID_FLAGS(func, bpf_cache_ext_handle_to_folio, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_handle_to_memcg, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_handle_to_ctx, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_evicted_ctx_to_handle)
BTF_ID_FLAGS(func, bpf_cache_ext_handle_to_evicted_ctx, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cgroup_to_memcg, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_folio_to_memcg, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_folio_to_node, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_folio_set_metadata)
BTF_ID_FLAGS(func, bpf_cache_ext_folio_add_metadata)
BTF_ID_FLAGS(func, bpf_cache_ext_node_set_metadata)
BTF_ID_FLAGS(func, bpf_cache_ext_node_add_metadata)
BTF_SET8_END(cache_ext_handle_ops)

static const struct btf_kfunc_id_set cache_ext_kfunc_set_handle_ops = {
    .owner = THIS_MODULE,
    .set = &cache_ext_handle_ops,
};

__bpf_kfunc int bpf_cache_ext_map_update(struct bpf_map* map,
                                         void* key, u32 key__sz,
                                         void* value, u32 value__sz)
{
  if (!map || !key || !value)
    return -EINVAL;
  if (key__sz != map->key_size || value__sz != map->value_size)
    return -EINVAL;

  rcu_read_lock();
  int err = map->ops->map_update_elem(map, key, value, BPF_ANY);
  rcu_read_unlock();

  return err;
}

__bpf_kfunc int bpf_cache_ext_map_delete(struct bpf_map* map,
                                         void* key, u32 key__sz)
{
  if (!map || !key)
    return -EINVAL;
  if (key__sz != map->key_size)
    return -EINVAL;

  rcu_read_lock();
  int err = map->ops->map_delete_elem(map, key);
  rcu_read_unlock();

  return err;
}

// 通用大结构体
struct cache_ext_val_buffer
{
  u8 raw_data[64];
};

__bpf_kfunc struct cache_ext_val_buffer*
bpf_cache_ext_map_lookup(struct bpf_map* map, void* key, u32 key__sz)
{
  if (!key || (key__sz != map->key_size))
    return NULL;

  return (struct cache_ext_val_buffer*)map->ops->map_lookup_elem(map, key);
}

// __bpf_kfunc int bpf_cache_ext_map_set_value(struct bpf_map* map,
//                                             void* key, u32 key__sz,
//                                             u32 offset,
//                                             void* value, u32 value__sz)
// {
//   if (key__sz != map->key_size)
//     return -EINVAL;
//   void* ptr = map->ops->map_lookup_elem(map, key);
//   if (!ptr)
//     return -ENOENT;
//   if (unlikely(offset + value__sz > map->value_size))
//     return -EINVAL;
//   memcpy(ptr + offset, value, value__sz);
//   return 0;
// }

#define DEFINE_CACHE_EXT_MAP_SET(type, suffix)                                        \
  __bpf_kfunc int bpf_cache_ext_map_set_##suffix(struct bpf_map* map, void* key,      \
                                                 u32 key__sz, u32 offset, type value) \
  {                                                                                   \
    if (key__sz != map->key_size)                                                     \
      return -EINVAL;                                                                 \
                                                                                      \
    void* ptr = map->ops->map_lookup_elem(map, key);                                  \
    if (!ptr)                                                                         \
      return -ENOENT;                                                                 \
                                                                                      \
    if (unlikely(offset + sizeof(type) > map->value_size))                            \
      return -EINVAL;                                                                 \
                                                                                      \
    *(type*)(ptr + offset) = value;                                                   \
    return 0;                                                                         \
  }

// 2. 一键展开，生成你需要的各种类型函数
DEFINE_CACHE_EXT_MAP_SET(u64, u64)
DEFINE_CACHE_EXT_MAP_SET(u32, u32)
DEFINE_CACHE_EXT_MAP_SET(bool, bool)

__bpf_kfunc s64 bpf_cache_ext_map_inc(struct bpf_map* map,
                                      void* key, u32 key__sz,
                                      u32 offset, s64 max_limit)
{
  if (key__sz != map->key_size)
    return -EINVAL;

  void* ptr = map->ops->map_lookup_elem(map, key);
  if (!ptr)
    return -ENOENT;
  if (unlikely(offset + sizeof(s64) > map->value_size))
    return -EINVAL;

  s64* target = (s64*)(ptr + offset);
  s64 old, new;
  do
  {
    old = READ_ONCE(*target);
    if (old >= max_limit)
      return old;
    new = old + 1;
  } while (cmpxchg(target, old, new) != old);
  return new;
}

__bpf_kfunc s64 bpf_cache_ext_map_dec(struct bpf_map* map,
                                      void* key, u32 key__sz,
                                      u32 offset, s64 min_limit)
{
  if (key__sz != map->key_size)
    return -EINVAL;

  void* ptr = map->ops->map_lookup_elem(map, key);
  if (!ptr)
    return -ENOENT;
  if (unlikely(offset + sizeof(s64) > map->value_size))
    return -EINVAL;

  s64* target = (s64*)(ptr + offset);
  s64 old, new;
  do
  {
    old = READ_ONCE(*target);
    if (old <= min_limit)
      return old;
    new = old - 1;
  } while (cmpxchg(target, old, new) != old);
  return new;
}

BTF_SET8_START(cache_ext_map_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_map_update)
BTF_ID_FLAGS(func, bpf_cache_ext_map_delete)
BTF_ID_FLAGS(func, bpf_cache_ext_map_lookup, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_cache_ext_map_set_u64) // 必须明确写出全名
BTF_ID_FLAGS(func, bpf_cache_ext_map_set_u32)
BTF_ID_FLAGS(func, bpf_cache_ext_map_set_bool)
BTF_ID_FLAGS(func, bpf_cache_ext_map_inc)
BTF_ID_FLAGS(func, bpf_cache_ext_map_dec)
BTF_SET8_END(cache_ext_map_ops)

static const struct btf_kfunc_id_set cache_ext_kfunc_set_map_ops = {
    .owner = THIS_MODULE,
    .set = &cache_ext_map_ops,
};

static int __init register_cache_ext_kfuncs(void)
{
  int ret;

  if ((ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_STRUCT_OPS, &cache_ext_kfunc_set_list_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_STRUCT_OPS, &cache_ext_kfunc_set_registry_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_STRUCT_OPS, &cache_ext_kfunc_set_handle_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_STRUCT_OPS, &cache_ext_kfunc_set_map_ops)))
  {
    pr_err("cache_ext: failed to register kfunc sets (%d)\n", ret);
    return ret;
  }
  if ((ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_TRACING, &cache_ext_kfunc_set_list_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_TRACING, &cache_ext_kfunc_set_registry_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_TRACING, &cache_ext_kfunc_set_handle_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_TRACING, &cache_ext_kfunc_set_map_ops)))
  {
    pr_err("cache_ext: failed to register TRACING kfuncs\n");
    return ret;
  }
  if ((ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_SYSCALL, &cache_ext_kfunc_set_list_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_SYSCALL, &cache_ext_kfunc_set_registry_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_SYSCALL, &cache_ext_kfunc_set_handle_ops)) ||
      (ret = register_btf_kfunc_id_set(
           BPF_PROG_TYPE_SYSCALL, &cache_ext_kfunc_set_map_ops)))
  {
    pr_err("cache_ext: failed to register SYSCALL kfuncs\n");
    return ret;
  }
  pr_info("version string lalakis1\n");

  pr_info("BTF IDs:\n");
  for (int i = 0; i < cache_ext_list_ops.cnt; i++)
  {
    pr_info("%d: %d\n", i, cache_ext_list_ops.pairs[i].id);
  }
  return 0;
}

__initcall(register_cache_ext_kfuncs);
