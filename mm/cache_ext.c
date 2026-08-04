#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#include <linux/memcontrol.h>
#include <linux/mm_types.h>
#include <linux/types.h>

static const struct btf_type* cache_ext_eviction_ctx_type;
static const struct btf_type* cache_ext_admission_ctx_type;
static const struct btf_type* cache_ext_list_node_type;
static const struct btf_type* mem_cgroup_type;

static int bpf_cache_ext_init(struct btf* btf)
{
  u32 eviction_type_id, admission_type_id, list_node_type_id, mem_cgroup_type_id;

  eviction_type_id = btf_find_by_name_kind(btf, "cache_ext_eviction_ctx",
                                           BTF_KIND_STRUCT);
  if (eviction_type_id < 0)
  {
    pr_err("cache_ext: failed to find struct cache_ext_eviction_ctx\n");
    return -EINVAL;
  }

  admission_type_id = btf_find_by_name_kind(btf, "cache_ext_admission_ctx",
                                            BTF_KIND_STRUCT);
  if (admission_type_id < 0)
  {
    pr_err("cache_ext: failed to find struct cache_ext_admission_ctx\n");
    return -EINVAL;
  }

  list_node_type_id = btf_find_by_name_kind(btf, "cache_ext_list_node",
                                            BTF_KIND_STRUCT);
  if (list_node_type_id < 0)
  {
    pr_err("cache_ext: failed to find struct cache_ext_list_node\n");
    return -EINVAL;
  }

  mem_cgroup_type_id = btf_find_by_name_kind(btf, "mem_cgroup",
                                              BTF_KIND_STRUCT);
  if (mem_cgroup_type_id < 0)
  {
    pr_err("cache_ext: failed to find struct mem_cgroup\n");
    return -EINVAL;
  }

  cache_ext_eviction_ctx_type = btf_type_by_id(btf, eviction_type_id);
  cache_ext_admission_ctx_type = btf_type_by_id(btf, admission_type_id);
  cache_ext_list_node_type = btf_type_by_id(btf, list_node_type_id);
  mem_cgroup_type = btf_type_by_id(btf, mem_cgroup_type_id);
  return 0;
}

// What helpers are available?
static const struct bpf_func_proto*
bpf_cache_ext_get_func_proto(enum bpf_func_id func_id,
                             const struct bpf_prog* prog)
{
  switch (func_id)
  {
  case BPF_FUNC_get_current_pid_tgid:
    return &bpf_get_current_pid_tgid_proto;
  default:
    return bpf_base_func_proto(func_id);
  }
}

// This is the verifier's check for context access. Context is always R1.
static bool bpf_cache_ext_is_valid_access(int off, int size,
                                          enum bpf_access_type type,
                                          const struct bpf_prog* prog,
                                          struct bpf_insn_access_aux* info)
{
  // 	return false;
  // if (type != BPF_READ)
  // 	return false;
  if (off % size != 0)
    return false;

  return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_cache_ext_btf_struct_access(struct bpf_verifier_log* log,
                                           const struct bpf_reg_state* reg,
                                           int off, int size)
{
  // For each of the allowed types, allow read access.
  const struct btf_type* t;

  t = btf_type_by_id(reg->btf, reg->btf_id);
  if (t == cache_ext_eviction_ctx_type)
  {
    if (off + size > sizeof(struct cache_ext_eviction_ctx))
    {
      bpf_log(log,
              "out of bounds access at off %d with size %d\n",
              off, size);
      return -EACCES;
    }
    return SCALAR_VALUE;
  }
  else if (t == cache_ext_admission_ctx_type)
  {
    if (off + size > sizeof(struct cache_ext_admission_ctx))
    {
      bpf_log(log,
              "out of bounds access at off %d with size %d\n",
              off, size);
      return -EACCES;
    }
    return SCALAR_VALUE;
  }
  else if (t == cache_ext_list_node_type)
  {
    if (off + size > sizeof(struct cache_ext_list_node))
    {
      bpf_log(log,
              "out of bounds access at off %d with size %d\n",
              off, size);
      return -EACCES;
    }
    return SCALAR_VALUE;
  }
  else if (t == mem_cgroup_type)
  {
    if (off + size > sizeof(struct mem_cgroup))
    {
      bpf_log(log,
              "out of bounds access at off %d with size %d\n",
              off, size);
      return -EACCES;
    }
    return SCALAR_VALUE;
  }

  return -EACCES;
}

static int bpf_cache_ext_reg(void* kdata, void* more_data)
{
  struct cache_ext_ops* ops = kdata;
  struct cgroup* cgrp = more_data;
  struct mem_cgroup* memcg;
  int ret = 0;

  if (!cgrp)
  {
    pr_err("cache_ext: cgroup is NULL\n");
    return -EINVAL;
  }

  // Get the memory cgroup
  memcg = mem_cgroup_from_css(cgrp->subsys[memory_cgrp_id]);
  if (memcg == NULL)
  {
    pr_crit("cache_ext: failed to get memcg for registration!\n");
    return -EINVAL;
  }
  pr_info("cache_ext: Calling init\n");
  if (ops->init)
  {
    ret = ops->init(memcg);
    if (ret)
    {
      pr_err("cache_ext: init failed with error code: %d\n",
             ret);
      cache_ext_ds_registry_del_all(memcg);
      return ret;
    }
  }

  pr_info("cache_ext: Registering struct ops\n");
  return 0;
}

static void bpf_cache_ext_unreg(void* kdata, void* more_data)
{
  struct cgroup* cgrp = more_data;
  struct mem_cgroup* memcg;

  pr_info("cache_ext: Unregistering struct ops\n");

  // Delete the registry and all data structures from the memory cgroup.
  if (!cgrp)
  {
    pr_err("cache_ext: cgroup is NULL\n");
    return;
  }

  memcg = mem_cgroup_from_css(cgrp->subsys[memory_cgrp_id]);
  if (memcg == NULL)
  {
    pr_crit("cache_ext: failed to get memcg for release!\n");
    return;
  }
  pr_info("cache_ext: unreg: Memcg pointer: %p\n", memcg);
  cache_ext_ds_registry_del_all(memcg);
}

static int bpf_cache_ext_init_member(const struct btf_type* t,
                                     const struct btf_member* member,
                                     void* kdata, const void* udata)
{
  // Initialize attributes of struct_ops. Not for the function pointers.
  // For example, sched_ext uses it to initialize timeout, flags, etc.
  // Not needed yet.
  return 0;
}

static int bpf_cache_ext_check_member(const struct btf_type* t,
                                      const struct btf_member* member,
                                      const struct bpf_prog* prog)
{
  // Check the attached member functions or attributes.
  // TODO: Check sleepability here!
  return 0;
}

static int bpf_cache_ext_validate(void* kdata)
{
  return 0;
}

static const struct bpf_verifier_ops bpf_cache_ext_verifier_ops = {
    .get_func_proto = bpf_cache_ext_get_func_proto,
    .is_valid_access = bpf_cache_ext_is_valid_access,
    .btf_struct_access = bpf_cache_ext_btf_struct_access,
};

// Callbacks to define the struct_ops map
struct bpf_struct_ops bpf_cache_ext_ops = {
    .verifier_ops = &bpf_cache_ext_verifier_ops,
    .init = bpf_cache_ext_init,
    .reg = bpf_cache_ext_reg,
    .unreg = bpf_cache_ext_unreg,
    .init_member = bpf_cache_ext_init_member,
    .check_member = bpf_cache_ext_check_member,
    .validate = bpf_cache_ext_validate,
    .name = "cache_ext_ops",
};
