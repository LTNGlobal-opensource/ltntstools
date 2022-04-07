#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hash_index.h"

struct hash_index_s *hash_index_alloc()
{
	struct hash_index_s *p = calloc(65535, sizeof(*p));
	return p;
}

void hash_index_free(struct hash_index_s *p)
{
	for (int i = 0; i < 65535; i++) {
		struct hash_index_s *e = p + i;
		if (e->arr) {
			free(e->arr);
			e->arr = NULL;
		}
	}
	free(p);
}

void hash_index_set(struct hash_index_s *p, uint16_t key, void *item)
{
	struct hash_index_s *e = p + key;
	e->arr = realloc(e->arr, (e->arrLength + 1) * sizeof(void *));
	//*(e->arr + (e->arrLength * sizeof(struct hash_index_s *))) = (void *)item;
	*(e->arr + e->arrLength) = (void *)item;

	e->arrLength++;
}

void *hash_index_get_first(struct hash_index_s *p, uint16_t key)
{
	struct hash_index_s *e = p + key;
	if (e->arrLength == 0)
		return NULL;

	return e->arr[0];
}

int hash_index_get_count(struct hash_index_s *p, uint16_t key)
{
	struct hash_index_s *e = p + key;
	return e->arrLength;
}

int hash_index_get_enum(struct hash_index_s *p, uint16_t key, int *enumer, void **ptr)
{
	struct hash_index_s *e = p + key;
	if (e->arrLength == 0)
		return -1;
	if (*enumer < 0 || *enumer >= e->arrLength)
		return -1;
	*ptr = e->arr[(*enumer)++];

	return 0;
}

void hash_index_print(struct hash_index_s *p, uint16_t key)
{
	struct hash_index_s *e = p + key;
	printf("Hash %04x index %p, length %d\n", key, e, hash_index_get_count(p, key));
	int enumer = 0;
	int ret = 0;
	while (ret == 0) {
		void *ptr = NULL;
		ret = hash_index_get_enum(p, key, &enumer, &ptr);
		printf("\tret %d, ptr %p\n", ret, ptr);
	}
}
