/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 *
 *   Robert Olsson <robert.olsson@its.uu.se> Uppsala Universitet
 *     & Swedish University of Agricultural Sciences.
 *
 *   Jens Laas <jens.laas@data.slu.se> Swedish University of 
 *     Agricultural Sciences.
 * 
 *   Hans Liss <hans.liss@its.uu.se>  Uppsala Universitet
 *
 * This work is based on the LPC-trie which is originally descibed in:
 * 
 * An experimental study of compression methods for dynamic tries
 * Stefan Nilsson and Matti Tikkanen. Algorithmica, 33(1):19-33, 2002.
 * http://www.nada.kth.se/~snilsson/public/papers/dyntrie2/
 *
 * IP-address lookup using LC-tries. Stefan Nilsson and Gunnar Karlsson
 * IEEE Journal on Selected Areas in Communications, 17(6):1083-1092, June 1999
 *
 */

#ifndef TRIE_H_
#define TRIE_H_

#include <string.h>

#ifdef HAVE_VARLIST_H
#include "varlist.h"
#endif

typedef unsigned int t_key;
typedef void * t_value;

#define TRIETRAV_SAFE

extern int debug;

typedef struct triestacknode_s
{
	int v1, v2, v3;
} triestacknode;

typedef struct triestack_s
{
	triestacknode *stack;
	int stacksz;
	int sp;
} *triestack;

typedef struct trietrav_handle_s
{
	struct trie *t;
#ifdef TRIETRAV_SAFE
	int trie_revision;
	t_key lastkey;
#endif
	int flags;
	triestack stack;
	int current_tn;
	int current_index;
	int depth;
} *trietrav_handle;

int trietrav_init(trietrav_handle *h, struct trie *t, int flags);
int trietrav_next(trietrav_handle *h, t_key *k, t_value *v, int *depth);
void trietrav_cleanup(trietrav_handle *h);

#define	T_FREE 0
#define	T_LEAF 1
#define	T_TNODE 2

struct leaf {
	t_key key;
	unsigned int type:2;
	t_value value;
};

struct tnode {
	t_key key;
	unsigned int type:2;
	unsigned int pos:6;
	unsigned int bits:6;
	unsigned int full_children;
	unsigned int empty_children;
	int children;
};

struct hole_s {
	int pos;
	int len;
};

struct trie {
	struct tnode *trie;
	int size;
	int allocsz;
	int endptr;
	int head;
	int halve_threshold;
	int inflate_threshold;
	struct hole_s *holes;
	int holes_allocsz;
	int holes_endptr;
#ifdef TRIETRAV_SAFE
	unsigned int revision;
#endif
};
    
void trie_sanity_check(struct trie *t, int node, int depth);
void trie_print_stat(struct trie *t);
void trie_dump(struct trie *t, int node);
#ifdef HAVE_VARLIST_H
void trie_dump_nl(namelist *v, struct trie *t);
#endif

void trie_set_low_threshold(struct trie *t, int n);
void trie_set_high_threshold(struct trie *t, int n);
struct trie *trie_new(void);
int trie_put(struct trie *t, t_key key, t_value value) ;
int trie_get(struct trie *t, t_key key, t_value *result);
int trie_is_empty(struct trie *t);
int trie_remove(struct trie *t, t_key key) ;
int trie_size(struct trie *t);
void trie_maint(struct trie *t);

/* Stats */
#define MAX_BITS 32

struct trie_stat {
	int totDepth;
	int maxDepth;
	int internalNodes;
	int leaves;
	int nullPointers;
	int nodeSizes[MAX_BITS+1];
};    

struct trie_stat *trie_stat_new(void);
void trie_collect_stat(struct trie *t, int node, int depth, struct trie_stat *s);

#endif /* TRIE_H_ */
