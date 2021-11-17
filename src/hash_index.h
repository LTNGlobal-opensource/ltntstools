#ifndef HASH_INDEX_H
#define HASH_INDEX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* Inputs are expected to be address in MSB */
extern uint16_t hash_index_cal_hash(uint32_t addr, uint16_t port);

/* (nic_monitor)
 * We need a hashing mechanism that lets us quickly lookup
 * entries in the context list of discovered_items,
 * which is significantly faster when we have 100+
 * streams to monitor.
 *
 * We take a destination ip address (unicast or multicast)
 * and its port, the hash transformation looksing like this,
 * Assuming each character is 4 bits.
 *
 * AB.CD.EF.GH:IJKL
 *
 * Hash: FGHL
 */
struct hash_index_s
{
	void **arr;
	unsigned int arrLength;
};

struct hash_index_s *hash_index_alloc();
void  hash_index_free(struct hash_index_s *p);
void  hash_index_set(struct hash_index_s *p, uint16_t key, void *item);

void *hash_index_get_first(struct hash_index_s *p, uint16_t key);
int   hash_index_get_count(struct hash_index_s *p, uint16_t key);

int   hash_index_get_enum(struct hash_index_s *p, uint16_t key, int *enumer, void **ptr);
void  hash_index_print(struct hash_index_s *p, uint16_t key);

#endif /* HASH_INDEX_H */
