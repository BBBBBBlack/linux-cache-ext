/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CACHE_EXT_GHOST_FIFO_CORE_H
#define CACHE_EXT_GHOST_FIFO_CORE_H

#include <linux/types.h>

/* All operations require the owner's lock. No pointers escape to callers.
 * Index 0 is NULL; slots 1..capacity are preallocated. Full keys, no fingerprint
 * approximation. Duplicate record = a new eviction event, refreshed to tail.
 */
struct ce_ghost_slot {
	u64 key0, key1;
	u32 hash_prev, hash_next;
	u32 prev, next;
	u32 bucket;
};

struct ce_ghost_fifo {
	struct ce_ghost_slot *slots;
	u32 *buckets;
	u32 capacity, count, head, tail, free_head;
};

static inline u32 ce_ghost_find(struct ce_ghost_fifo *q, u32 bucket,
			      u64 key0, u64 key1)
{
	u32 i;

	for (i = q->buckets[bucket]; i; i = q->slots[i].hash_next)
		if (q->slots[i].key0 == key0 && q->slots[i].key1 == key1)
			return i;
	return 0;
}

static inline void ce_ghost_unlink_fifo(struct ce_ghost_fifo *q, u32 i)
{
	struct ce_ghost_slot *s = &q->slots[i];

	if (s->prev)
		q->slots[s->prev].next = s->next;
	else
		q->head = s->next;
	if (s->next)
		q->slots[s->next].prev = s->prev;
	else
		q->tail = s->prev;
}

static inline void ce_ghost_unlink_hash(struct ce_ghost_fifo *q, u32 i)
{
	struct ce_ghost_slot *s = &q->slots[i];

	if (s->hash_prev)
		q->slots[s->hash_prev].hash_next = s->hash_next;
	else
		q->buckets[s->bucket] = s->hash_next;
	if (s->hash_next)
		q->slots[s->hash_next].hash_prev = s->hash_prev;
}

static inline void ce_ghost_append(struct ce_ghost_fifo *q, u32 i)
{
	q->slots[i].prev = q->tail;
	q->slots[i].next = 0;
	if (q->tail)
		q->slots[q->tail].next = i;
	else
		q->head = i;
	q->tail = i;
}

/* Returns 1 for a new key, 0 for a refreshed existing key. */
static inline int ce_ghost_record(struct ce_ghost_fifo *q, u32 bucket,
				  u64 key0, u64 key1)
{
	u32 i = ce_ghost_find(q, bucket, key0, key1);
	struct ce_ghost_slot *s;

	if (i) {
		ce_ghost_unlink_fifo(q, i);
		ce_ghost_append(q, i);
		return 0;
	}
	if (q->count == q->capacity) {
		i = q->head;
		ce_ghost_unlink_fifo(q, i);
		ce_ghost_unlink_hash(q, i);
	} else {
		i = q->free_head;
		q->free_head = q->slots[i].next;
		q->count++;
	}
	s = &q->slots[i];
	s->key0 = key0;
	s->key1 = key1;
	s->bucket = bucket;
	s->hash_prev = 0;
	s->hash_next = q->buckets[bucket];
	if (s->hash_next)
		q->slots[s->hash_next].hash_prev = i;
	q->buckets[bucket] = i;
	ce_ghost_append(q, i);
	return 1;
}

/* Removing a hit immediately creates a free slot: no tombstones or expiry. */
static inline bool ce_ghost_consume(struct ce_ghost_fifo *q, u32 bucket,
				   u64 key0, u64 key1)
{
	u32 i = ce_ghost_find(q, bucket, key0, key1);

	if (!i)
		return false;
	ce_ghost_unlink_fifo(q, i);
	ce_ghost_unlink_hash(q, i);
	q->slots[i].next = q->free_head;
	q->free_head = i;
	q->count--;
	return true;
}

#endif
