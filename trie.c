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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trie.h"

#undef DEBUG_TRIEOP
#undef DEBUG_TNODE
#undef DEBUG_MAIN
#undef DEBUG_SLAB

#define KEYLENGTH (8*sizeof(t_key))

#define tkey_extract_bits(a, offset, bits) (((bits)==0)?0:(((offset) < KEYLENGTH)?(((t_key)((a) << (offset))) >> (KEYLENGTH - (bits))):0))
#define tkey_equals(a, b) ((a)==(b))
#define tkey_sub_equals(a, offset, bits, b) (((bits)==0 || ((offset) >= KEYLENGTH))?1: \
					     (((t_key)((a)^(b)) << (offset)) >> (KEYLENGTH - \
										 (((bits) > KEYLENGTH)?KEYLENGTH:(bits))) == 0))
static inline t_key tkey_mismatch(a, offset, b)
{
	t_key diff = a ^ b;
	int i = offset;

	if(!diff) 
		return 0;
	while((diff << i) >> (KEYLENGTH-1) == 0)
		i++;
	return i;
}

#define TKEY_GET_MASK(offset, bits) (((bits)==0)?0:((t_key)(-1) << (KEYLENGTH - bits) >> offset))

#define IS_FREE(t, num) ((t)->trie[num].type == T_FREE)
#define IS_LEAF(t, num) ((t)->trie[num].type == T_LEAF)
#define IS_TNODE(t, num) ((t)->trie[num].type == T_TNODE)

#define NODE(t, node) ((t)->trie[(node)])
#define CHILDREN(t, node) ((t)->trie[(node)].children)
#define CHILD(t, node, i) ((t)->trie[(node)].children + (i))
#define TYPE(t, node) ((t)->trie[(node)].type)
#define KEY(t, node) ((t)->trie[(node)].key)
#define VALUE(t, node) (((struct leaf *)&((t)->trie[(node)]))->value)
#define POS(t, node) ((t)->trie[(node)].pos)
#define BITS(t, node) ((t)->trie[(node)].bits)
#define NCHILDREN(t, node) (1 << ((t)->trie[(node)].bits))

static void tnode_resize(struct trie *t, int tp, int tc);
static void tnode_inflate(struct trie *t, int node, triestack st);
static void tnode_halve(struct trie *t, int node, triestack st);
static void trie_addhole(struct trie *t, int pos, int len);
static int trie_gethole(struct trie *t, int len);

#define ALLOC(N) calloc(1, N)

#define FREE(n) free(n)

typedef struct triefifo_s
{
	triestacknode *fifo;
	int fifosz;
	int hp;
	int tp;
} *triefifo;

static inline void triestack_init(triestack *stack)
{
	if ((*stack) == NULL) {
		(*stack)=ALLOC(sizeof(struct triestack_s));
		if (!(*stack)) {
			perror("malloc()");
			exit(-1);
		}
		memset((*stack), 0, sizeof(struct triestack_s));
		(*stack)->stacksz=10;
		(*stack)->stack=ALLOC((*stack)->stacksz * sizeof(triestacknode));
		if (!((*stack)->stack))	{
			perror("malloc()");
			exit(-1);
		}
	}
	(*stack)->sp=0;
}

static inline void triestack_push(triestack st, int v1, int v2, int v3)
{
	if (st->sp == st->stacksz) {
		int newsize=st->stacksz + (st->stacksz >> 1);
		triestacknode *newst=ALLOC(newsize * sizeof(triestacknode));
		if (!newst) {
			perror("malloc()");
			exit(-1);
		}
		memcpy(newst, st->stack, st->sp * sizeof(triestacknode));
		FREE(st->stack);
		(st->stack)=newst;
		st->stacksz=newsize;
	}
	st->stack[st->sp].v1=v1;
	st->stack[st->sp].v2=v2;
	st->stack[st->sp].v3=v3;
	st->sp++;
}

static inline int triestack_pop(triestack st, int *v1, int *v2, int *v3)
{
	int r;
	if (st->sp > 0) {
		st->sp--;
		if (v1) (*v1)=st->stack[st->sp].v1;
		if (v2) (*v2)=st->stack[st->sp].v2;
		if (v3) (*v3)=st->stack[st->sp].v3;
		r=0;
	}
	else {
		if (v1) (*v1)=-1;
		if (v2) (*v2)=-1;
		if (v3) (*v3)=-1;
		r=-1;
	}
	return r;
}

static inline void triestack_cleanup(triestack *st, int freeit)
{
	if (freeit) {
		FREE((*st)->stack);
		free(*st);
		(*st)=NULL;
	} else {
		(*st)->sp=0;
	}
}

static inline void triefifo_init(triefifo *fifo)
{
	if ((*fifo) == NULL) {
		(*fifo)=ALLOC(sizeof(struct triefifo_s));
		if (!(*fifo)) {
			perror("malloc()");
			exit(-1);
		}
		memset((*fifo), 0, sizeof(struct triefifo_s));
		(*fifo)->fifosz=10;
		(*fifo)->fifo=ALLOC((*fifo)->fifosz * sizeof(triestacknode));
		if (!((*fifo)->fifo)) {
			perror("malloc()");
			exit(-1);
		}
	}
	(*fifo)->hp=(*fifo)->tp=0;
}

/* Add data to the head of the fifo */
static inline void triefifo_push(triefifo fifo, int v1, int v2, int v3)
{
	/* Never let head and tail meet when the fifo is filling up! */
	if ((fifo->tp - fifo->hp + fifo->fifosz) % fifo->fifosz == 1) {
		int newsize=fifo->fifosz + (fifo->fifosz >> 1);
		triestacknode *newfifo=ALLOC(newsize*sizeof(triestacknode));
		if (!newfifo) {
			perror("malloc()");
			exit(-1);
		}
		if (fifo->hp < fifo->tp) {
			memcpy(newfifo, fifo->fifo, fifo->hp * sizeof(triestacknode));
			memcpy(newfifo+(newsize-(fifo->fifosz - fifo->tp)),
			       fifo->fifo + fifo->tp,
			       (fifo->fifosz - fifo->tp) * sizeof(triestacknode));
			fifo->tp += newsize - fifo->fifosz;
		} else {
			memcpy(newfifo, fifo->fifo, fifo->fifosz * sizeof(triestacknode));
		}
		FREE(fifo->fifo);
		fifo->fifo = newfifo;
		fifo->fifosz = newsize;
	}
	fifo->fifo[fifo->hp].v1=v1;
	fifo->fifo[fifo->hp].v2=v2;
	fifo->fifo[fifo->hp].v3=v3;
	fifo->hp = (fifo->hp+1) % fifo->fifosz;
}

/* Take data from the tail of the fifo */
static inline int triefifo_pop(triefifo fifo, int *v1, int *v2, int *v3)
{
	int r;
	if ((fifo->hp - fifo->tp + fifo->fifosz) % fifo->fifosz > 0) {
		if (v1) (*v1)=fifo->fifo[fifo->tp].v1;
		if (v2) (*v2)=fifo->fifo[fifo->tp].v2;
		if (v3) (*v3)=fifo->fifo[fifo->tp].v3;
		fifo->tp = (fifo->tp+1) % fifo->fifosz;
		r=0;
	}
	else {
		if (v1) (*v1)=-1;
		if (v2) (*v2)=-1;
		if (v3) (*v3)=-1;
		r=-1;
	}
	return r;
}

static inline void triefifo_cleanup(triefifo *fifo, int freeit)
{
	if (freeit)
	{
		FREE((*fifo)->fifo);
		free(*fifo);
		(*fifo)=NULL;
	}
	else
	{
		(*fifo)->hp=(*fifo)->tp=0;
	}
}

int tnode_is_lc(struct trie *t, int tn);

/* tnode.c */
/*
 * Check whether a child tnode is a 'full' child, i.e. it is an internal node
 * and no bits are skipped. See discussion in dyntree paper p. 6
 */
static inline void tnode_get_fullempty_node(struct trie *t, int p, int c, int *full, int *empty)
{
	if (c == -1 || IS_FREE(t, c)) {
		*full = 0;
		*empty = 1;
	}
	else if (IS_LEAF(t, c)) {
		*full = 0;
		*empty = 0;
	}
	else {
		*empty=0;
		*full=(POS(t, c) == POS(t, p) + BITS(t, p))?1:0;
	}
}

static inline void tnode_get_fullempty(struct trie *t, int p, int cindex, int *full, int *empty)
{
	tnode_get_fullempty_node(t, p, CHILD(t, p, cindex), full, empty);
}

/* 
 * Update the value of full_children and empty_children.
 */

static inline void tnode_update_fullempty_node(struct trie *t, int p, int c, int wasfull, int wasempty) 
{
	int isfull, isempty;

	tnode_get_fullempty_node(t, p, c, &isfull, &isempty);

	/* update empty_children */

	if (isempty && !wasempty)
		NODE(t, p).empty_children++;
	else if (!isempty && wasempty)
		NODE(t, p).empty_children--;
  
	/* update full_children */

	if (wasfull && !isfull)
		NODE(t, p).full_children--;
	else if (!wasfull && isfull)
		NODE(t, p).full_children++;
}

static inline void tnode_update_fullempty(struct trie *t, int p, int pos, int wasfull, int wasempty) 
{
	tnode_update_fullempty_node(t, p, CHILD(t, p, pos), wasfull, wasempty);
}


struct trie *trie_new(void)
{
	struct trie *t = ALLOC(sizeof(struct trie));
	if(t) {
		t->size = 0;
#ifdef TRIETRAV_SAFE
		t->revision = 0;
#endif
		t->allocsz=500;
		t->endptr=0;
		if (!(t->trie = ALLOC(sizeof(struct tnode) * t->allocsz))) {
			perror("malloc()");
			exit(-1);
		}
		t->holes_allocsz=50;
		t->holes_endptr=0;
		if (!(t->holes = ALLOC(sizeof(struct hole_s) * t->holes_allocsz))) {
			perror("malloc()");
			exit(-1);
		}
		t->head=-1;
		t->halve_threshold = 75;
		t->inflate_threshold = 50;
	}
	return t;
}

static int trie_expand(struct trie *t)
{
	int newsize=t->allocsz + (t->allocsz >> 1);
	struct tnode *newarr;
#ifdef DEBUG_MAIN
	fprintf(stderr, "Expanding trie from %d to %d nodes\n", t->allocsz, newsize);
#endif
	if (!(newarr=ALLOC(sizeof(struct tnode) * newsize)))
	{
		perror("malloc()");
		exit(-1);
	}
	memcpy(newarr, t->trie, t->endptr * sizeof(struct tnode)); /* copy the nodes that have values */
	FREE(t->trie);
	t->trie=newarr;
	t->allocsz=newsize;
	return 0;
}

static void expandholes(struct trie *t)
{
	int newsize = t->holes_allocsz + (t->holes_allocsz >> 1);
	struct hole_s *newarr=ALLOC(sizeof(struct hole_s) * newsize);
	if (!newarr)
	{
		perror("malloc()");
		exit(-1);
	}
	memcpy(newarr, t->holes, t->holes_endptr * sizeof(struct hole_s));
	FREE(t->holes);
	t->holes=newarr;
	t->holes_allocsz=newsize;
}

static inline int major_ahole(struct trie *t, int *pos_a, int *len_a)
{
	int pos=*pos_a, len=*len_a;
	int i, empty=-1, end=pos + len;
	for (i = 0; i < t->holes_endptr; i++) {
		if (t->holes[i].len > 0) {
			if (t->holes[i].pos == end) {
				len += t->holes[i].len;
				end += t->holes[i].len;
				t->holes[i].len = 0;
				if (empty==-1)
					empty=i;
			} else if (t->holes[i].pos + t->holes[i].len == pos) {
				pos -= t->holes[i].len;
				len += t->holes[i].len;
				t->holes[i].len = 0;
				if (empty==-1)
					empty=i;
			} 
		} else if (empty == -1)
			empty = i;
	}
	*pos_a = pos;
	*len_a = len;
	return empty;
}

static inline void minor_ahole(struct trie *t, int empty, int pos, int len)
{
	if (pos+len == t->endptr)
		t->endptr=pos;
	else
	{
		/* Did we find an unused hole? */
		if (empty != -1) {
			t->holes[empty].pos=pos;
			t->holes[empty].len=len;
			return;
		}
		else if (t->holes_endptr >= t->holes_allocsz)
			expandholes(t);
		t->holes[t->holes_endptr].pos = pos;
		t->holes[t->holes_endptr].len = len;
		t->holes_endptr++;
	}
}

static int holy_compare_func(const void *ap, const void *bp)
{
	struct hole_s *a=(struct hole_s*)ap;
	struct hole_s *b=(struct hole_s*)bp;
	if (a->len==0) return 1;
	if (b->len==0) return -1;
	return (a->pos>b->pos)?1:((a->pos<b->pos)?-1:0);
}

static inline void trie_addhole(struct trie *t, int pos, int len)
{
	int empty=-1;
	/* try to find a hole that can be expanded */
#ifdef DEBUG_SLAB
	if (debug)
		printf("Hole of len %d at %d returned\n", len, pos);
#endif
	empty=major_ahole(t, &pos, &len);
	minor_ahole(t, empty, pos, len);
	return;
}

static inline int trie_gethole(struct trie *t, int len)
{
	int i, pos=-1, found=-1;
	/* try to find an already empty hole */
#ifdef DEBUG_SLAB
	if (debug>3) {
		printf("New hole of len %d requested\n", len);
	}
#endif
	for (i=0;i < t->holes_endptr; i++)
		if (t->holes[i].len >= len) {
			if (found==-1 || t->holes[i].len < t->holes[found].len)
				found=i;
		}
	if (found > -1) {
		pos=t->holes[found].pos;
		t->holes[found].pos+=len;
		t->holes[found].len-=len;
	}
	if (pos == -1) {
		/* nope, try to add us to the end of the array */
		while (t->endptr + len > t->allocsz)
			trie_expand(t);
		pos=t->endptr;
		t->endptr+=len;
	}
	memset(&(t->trie[pos]), 0, len * sizeof(struct tnode));
#ifdef DEBUG_SLAB
	if (debug>3) {
		printf("found %d, endptr=%d, cleared nodes %d", found, t->endptr, pos);
		for (i=pos+1; i<pos+len; i++)
			printf(",%d", i);
		printf("\n");
	}
	if (debug)
		printf("New hole of len %d requested, got %d - %d\n", len, pos, pos+len-1);
#endif
	return pos;
}

void trie_maint(struct trie *t)
{
	int i, count=0, count2=0, count3=t->holes_endptr;
	int smallholes=0, largeholes=0;
	double holeratio, sholes, lholes;
	qsort(t->holes, t->holes_allocsz, sizeof(struct hole_s), holy_compare_func);
	for (i=0; i < t->holes_endptr; i++) {
		if (t->holes[i].len>0) {
			count++;
			if (i < (t->holes_endptr+1) && t->holes[i+1].len>0 &&
			    t->holes[i].pos+t->holes[i].len == t->holes[i+1].pos) {
				t->holes[i+1].pos-=t->holes[i].len;
				t->holes[i+1].len+=t->holes[i].len;
				t->holes[i].len=0;
			}
			if (t->holes[i].len>0)
				count2++;
		}
	}
	qsort(t->holes, t->holes_allocsz, sizeof(struct hole_s), holy_compare_func);
	while (t->holes_endptr>0 && t->holes[t->holes_endptr-1].len==0)
		t->holes_endptr--;
	for (i=0; i < t->holes_endptr; i++) {
		if (t->holes[i].len>0) {
			if (t->holes[i].len>10)
				largeholes+=t->holes[i].len;
			else
				smallholes+=t->holes[i].len;
		}
	}
	if (t->endptr>0)
		holeratio=100*((double)(largeholes+smallholes)/t->endptr);
	else
		holeratio=0;
	if (largeholes+smallholes>0) {
		lholes=100*((double)largeholes/(largeholes+smallholes));
		sholes=100*((double)smallholes/(largeholes+smallholes));
	} else {
		lholes=sholes=0;
	}
	printf("trie_maint(): holes/endptr before: %d/%d, holes_endptr after: %d/%d\n", count, count3, count2, t->holes_endptr);
	printf("trie_maint(): empty space: %0.4g%%, of which large holes %0.4g%% and small holes %0.4g%%\n",
	       holeratio, lholes, sholes);
	       
	       
}

void trie_set_low_threshold(struct trie *t, int n) 
{
	if (0 <= n && n <= 100)
		t->halve_threshold = n;
}

void trie_set_high_threshold(struct trie *t, int n) 
{
	if (0 <= n && n <= 100)
		t->inflate_threshold = n;
}

/*
 * Check whether a tnode's child 'n' is "full", i.e. it is an internal node
 * and no bits are skipped. See discussion in dyntree paper p. 6
 */

static void tnode_resize(struct trie *t, int tp, int tc) 
{
	int i, cl;
	static triestack stack=NULL;

	triestack_init(&stack);

#ifdef DEBUG_TNODE
	if(debug) 
		trie_dump(t, tp);
#endif

	/* No children */

	triestack_push(stack, tp, tc, 0);

	while ((triestack_pop(stack, &tp, &tc, NULL))!=-1) {

		int wasfull, wasempty;

		if (!IS_TNODE(t, tc))
			continue;

		if (tp != -1 && IS_TNODE(t, tp))
			tnode_get_fullempty_node(t, tp, tc, &wasfull, &wasempty);

		cl = NCHILDREN(t, tc);

		if (NODE(t, tc).empty_children == cl) {
			trie_addhole(t, CHILDREN(t, tc), NCHILDREN(t, tc));
			TYPE(t, tc)=T_FREE;
			if (tp != -1)
				tnode_update_fullempty_node(t, tp, tc, wasfull, wasempty);
			continue;
		}

		/* One child */
		if (NODE(t, tc).empty_children == cl - 1) {
			for (i = 0; i < cl; i++)
				if (!IS_FREE(t, CHILD(t, tc, i))) {
					int oldpos=CHILDREN(t, tc);
					int oldlen=NCHILDREN(t, tc);
#ifdef DEBUG_TNODE
					if (debug)
						printf("Moving %d (%08x, child %d of %d) to %d\n", oldpos+i, KEY(t, oldpos+i), i, tc, tc);
#endif
					/* compress one level */
					memcpy(&(NODE(t, tc)), &(NODE(t, oldpos+i)), sizeof(struct tnode));
					trie_addhole(t, oldpos, oldlen);
					if (tp != -1)
						tnode_update_fullempty_node(t, tp, tc, wasfull, wasempty);
					break;
				}
			continue;
		}

		/* 
		 * Double as long as the resulting node has a number of
		 * nonempty nodes that are above the threshold.
		 */


		if (NODE(t, tc).full_children > 0 &&
		    50 * (NODE(t, tc).full_children + NCHILDREN(t, tc) - NODE(t, tc).empty_children) >=
		    t->inflate_threshold * NCHILDREN(t, tc)) {
			triestack_push(stack, tp, tc, 0);
			tnode_inflate(t, tc, stack);
			if (tp != -1)
				tnode_update_fullempty_node(t, tp, tc, wasfull, wasempty);
			continue;
		}

		/*
		 * Halve as long as the number of empty children in this
		 * node is above threshold.
		 */

		if (BITS(t, tc) > 1 &&
		    100 * NODE(t, tc).empty_children >
		    t->halve_threshold * NCHILDREN(t, tc)) {
			triestack_push(stack, tp, tc, 0);
			tnode_halve(t, tc, stack);
			if (tp != -1)
				tnode_update_fullempty_node(t, tp, tc, wasfull, wasempty);
			continue;
		}

	}
	triestack_cleanup(&stack, 0);
}

void tnode_inflate(struct trie *t, int tn, triestack st)
{
	int oldchildren = CHILDREN(t, tn), newchildren;
	int olen = NCHILDREN(t, tn);
	int i;
	int oldbits = BITS(t, tn);
  
#ifdef DEBUG_TNODE
	if(debug) printf("In tnode_inflate\n");
#endif

	BITS(t, tn)++;
	NODE(t, tn).empty_children += olen;
	newchildren=trie_gethole(t, 2*olen);

#ifdef DEBUG_TNODE
	if (debug)
		printf("children of %d moved from %d to %d\n", tn, oldchildren, newchildren);
#endif
	CHILDREN(t, tn)=newchildren;
	for(i = 0; i < olen; i++) {
		int node = oldchildren+i;
		int newplace=newchildren + 2*i;
      
		/* An empty child */

		if (IS_FREE(t, node))
			continue;

		/* A leaf or an internal node with skipped bits. neither empty_children or full_children will change */

		if(IS_LEAF(t, node) || POS(t, node) > POS(t, tn) + oldbits) {
			int offset=(tkey_extract_bits(KEY(t, node), POS(t, tn) + oldbits, 1) == 0)?0:1;
#ifdef DEBUG_TNODE
			if (debug)
				printf("moving %d to %d (%08x, child %d of %d)\n", node, newplace + offset, KEY(t, node), i*2 + offset, tn);
#endif
			if (IS_TNODE(t, node) && (POS(t, node) == POS(t, tn) + BITS(t, tn)))
				NODE(t, tn).full_children++;
			memcpy(&(NODE(t, newplace + offset)),
			       &(NODE(t, node)), sizeof(struct tnode));
			continue;
		}
		/* An internal node with two children */

		if (BITS(t, node) == 1) {
			NODE(t, tn).empty_children -= (1 - NODE(t, node).empty_children);
			NODE(t, tn).full_children += NODE(t, node).full_children-1;
#ifdef DEBUG_TNODE
			if (debug)
				printf("moving %d and %d (%08x and %08x) to %d and %d (child %d and %d of %d)\n",
				       CHILD(t, node, 0), CHILD(t, node, 1), KEY(t, CHILD(t, node, 0)),
				       KEY(t, CHILD(t, node, 1)), newplace, newplace+1, 2*i, 2*i+1, tn);
#endif
			memcpy(&(NODE(t, newplace)), &(NODE(t, CHILDREN(t, node))), 2*sizeof(struct tnode));
			trie_addhole(t, CHILDREN(t, node), 2);
		}

		/* An internal node with more than two children */
		else {
			int left, right;

			/* We will replace this node 'inode' with two new 
			 * ones, 'left' and 'right', each with half of the 
			 * original children. The two new nodes will have 
			 * a position one bit further down the key and this 
			 * means that the "significant" part of their keys 
			 * (see the discussion near the top of this file) 
			 * will differ by one bit, which will be "0" in 
			 * left's key and "1" in right's key. Since we are 
			 * moving the key position by one step, the bit that 
			 * we are moving away from - the bit at position 
			 * (inode->pos) - is the one that will differ between 
			 * left and right. So... we synthesize that bit in the
			 * two  new keys.
			 * The mask 'm' below will be a single "one" bit at 
			 * the position (inode->pos)
			 */

			left = right = CHILD(t, tn, 2 * i);
			right++;
			t_key m = TKEY_GET_MASK(POS(t, node), 1);

			POS(t, node)++;
			BITS(t, node)--;

			memcpy(&(NODE(t, left)), &(NODE(t, node)), sizeof(struct tnode));
			memcpy(&(NODE(t, right)), &(NODE(t, node)), sizeof(struct tnode));
 
			/* Use the old key, but set the new significant 
			 *   bit to zero. 
			 */

			KEY(t, left) &= (~m);
			KEY(t, right) |= m;

			CHILDREN(t, right) += NCHILDREN(t, right);

#ifdef DEBUG_TNODE
			if (debug)
				printf("building %d and %d to handle the children of %d - their children are at %d and %d\n",
				       left, right, node, CHILDREN(t, left), CHILDREN(t, right));
#endif

			NODE(t, tn).full_children++;
			NODE(t, tn).empty_children--;

			{
				int cl=CHILDREN(t, left);
				int cr=CHILDREN(t, right);
				int npos=POS(t, left) + BITS(t, left);
				int ecl=0, ecr=0, fcl=0, fcr=0;
				int i, l = NCHILDREN(t, left);
				for (i=0; i<l; i++)
				{
					if (IS_FREE(t, cl+i))
						ecl++;
					if (IS_FREE(t, cr+i))
						ecr++;
					if (IS_TNODE(t,cl+i) && POS(t, cl+i)==npos)
						fcl++;
					if (IS_TNODE(t,cr+i) && POS(t, cr+i)==npos)
						fcr++;
				}
				NODE(t, left).empty_children=ecl;
				NODE(t, left).full_children=fcl;
				NODE(t, right).empty_children=ecr;
				NODE(t, right).full_children=fcr;
			}

#ifdef DEBUG_TNODE
			if (debug)
				printf("f/e is %d/%d and %d/%d\n",
				       NODE(t, left).full_children, NODE(t, left).empty_children,
				       NODE(t, right).full_children, NODE(t, right).empty_children);
#endif

			TYPE(t, node)=T_FREE;
			triestack_push(st, tn, left, 0);
			triestack_push(st, tn, right, 0);
		}
	}
	trie_addhole(t, oldchildren, olen);
#ifdef DEBUG_TNODE
	if (debug)
		trie_dump(t, t->head);
#endif
}

void tnode_halve(struct trie *t, int tn, triestack st)
{
	int olen = NCHILDREN(t, tn);
	int left, right, c;
	int i;

#ifdef DEBUG_TNODE
	if(debug) printf("In tnode_halve\n");
#endif

	BITS(t, tn)--;

	NODE(t, tn).full_children = 0;
	NODE(t, tn).empty_children = NCHILDREN(t, tn);
	for(i = 0; i < olen; i += 2) {
		left = CHILD(t, tn, i);
		right = CHILD(t, tn, i+1);
		c=CHILD(t, tn, i/2);
    
		/* At least one of the children is empty */
		if (IS_FREE(t, left)) {
			if (IS_FREE(t, right)) {    /* Both are empty */
#ifdef DEBUG_TNODE
				if (debug)
					printf("Setting %d as free, both %d and %d are free\n", c, left, right);
#endif
				TYPE(t, c)=T_FREE;
			}
			else {
#ifdef DEBUG_TNODE
				if (debug)
					printf("Moving %d (%08x) to %d, %d is free\n", right, KEY(t, right), c, left);
#endif
				memcpy(&(NODE(t, c)), &(NODE(t, right)), sizeof(struct tnode));
			}
		} else if (IS_FREE(t, right)) {
#ifdef DEBUG_TNODE
			if (debug)
				printf("Moving %d (%08x) to %d, %d is free\n", left, KEY(t, left), c, right);
#endif
			memcpy(&(NODE(t, c)), &(NODE(t, left)), sizeof(struct tnode));
		}
     
		/* Two nonempty children */
		else {
			int newchildren;
#ifdef DEBUG_TNODE
			if (debug)
				printf("Making a tnode in %d for %d and %d\n", c, left, right);
#endif
			KEY(t, c)=KEY(t, left);
			newchildren=trie_gethole(t, 2);
			memcpy(&(NODE(t, newchildren)), &(NODE(t, left)), sizeof(struct tnode));
			memcpy(&(NODE(t, newchildren+1)), &(NODE(t, right)), sizeof(struct tnode));
			TYPE(t, c)=T_TNODE;
			POS(t, c)=POS(t, tn) + BITS(t, tn);
			BITS(t, c)=1;
			NODE(t, c).empty_children=0;
			NODE(t, c).full_children=0;
			CHILDREN(t, c)=newchildren;
			tnode_update_fullempty(t, c, 0, 0, 0);
			tnode_update_fullempty(t, c, 1, 0, 0);
			triestack_push(st, tn, c, 0);
		}
		tnode_update_fullempty(t, tn, i/2, 0, 1);
	}
	trie_addhole(t, CHILDREN(t, tn) + (olen/2), olen/2);
}

int trie_is_empty(struct trie *t) 
{
        return (t->size == 0);
}

/*
 * Returns the number of keys in this trie.
 */

int trie_size(struct trie *t) 
{
        return t->size;
}

/* 
 * Search for associated specified key.
 * Returns 1 and sets 'result' to the value, or 0 on failure
 */

int trie_get(struct trie *t, t_key key, t_value *result)
{
	int current_node=t->head;
	int r=1;

#ifdef DEBUG_TRIEOP	
	if(debug) printf("trie_get\n");        
#endif
	
        while (current_node != -1 && IS_TNODE(t, current_node)) {
		current_node=CHILD(t, current_node, tkey_extract_bits(key, POS(t, current_node), BITS(t, current_node)));
        }
	if (current_node != -1 && !IS_FREE(t, current_node) && tkey_equals(KEY(t, current_node), key)) {
		*result=VALUE(t, current_node);
		r=0;
	}
	return r;
}


int trie_remove(struct trie *t, t_key key) 
{
	t_key cindex=0;
	int wasfull=0, wasempty=0;
	int tp, tc;
	triestack stack=NULL;
	int current_node=t->head;
	int r=1;
	triestack_init(&stack);

#ifdef DEBUG_TRIEOP
	if (debug>3)
		trie_dump(t, t->head);
	else if(debug) 
		printf("entering trie_remove(%p,0x%08x)\n", t, key);
#endif

	/* Walk the tree and fill the stack. Note that in the case of 
	 * skipped bits, those bits are *not* checked!
	 * When we finish this, we will have -1 or a T_LEAF, and the 
	 * T_LEAF may or may not match our key.
	 * While walking the tree we push the nodes we pass on the stack.
	 */
	
        while (current_node != -1 && IS_TNODE(t, current_node)) {
		triestack_push(stack, current_node, 0, 0);
		current_node=CHILD(t, current_node, tkey_extract_bits(key, POS(t, current_node), BITS(t, current_node)));
        }

#ifdef DEBUG_TRIEOP
	if (debug)
		printf("found %d\n", current_node);
#endif
	if (current_node != -1 && IS_LEAF(t, current_node) && tkey_equals(KEY(t, current_node), key)) {
		/* Key found. Remove the leaf and rebalance the tree */

		/* Let the loop below handle everything - just feed it a NULL 
		 * child to start out with 
		 */

		triestack_pop(stack, &tp, NULL, NULL);
		if (tp != -1) {
			cindex = tkey_extract_bits(key, POS(t, tp), BITS(t, tp));
			tnode_get_fullempty(t, tp, cindex, &wasfull, &wasempty);
		}
		else
			trie_addhole(t, current_node, 1);
		t->size--;
		TYPE(t, current_node)=T_FREE;
		tc = -1;
		if (tp != -1)
			tnode_update_fullempty(t, tp, cindex, wasfull, wasempty);

		/* Pop a parent from the stack, save the "fullness" value of 
		 * the old child,  reorganize it and update the fullness value
		 * in the parent.
		 */
	  
		while (tp != -1) {
			if (tc != -1 && IS_TNODE(t, tc)) {
				tnode_resize(t, tp, tc);
			}
			tc = tp;
			triestack_pop(stack, &tp, NULL, NULL);
		}
		
		if (tc != -1 && IS_TNODE(t, tc)) {
			tnode_resize(t, tp, tc);
		}
#ifdef DEBUG_TRIEOP
		if (t->head != tc)
			printf("***setting head to %d\n", tc);
#endif
		t->head=tc;
#ifdef DEBUG_TRIEOP
		if (debug>3)
			trie_dump(t, tc);
#endif
#ifdef TRIETRAV_SAFE
		t->revision++;
#endif
		r=0;
	}
	triestack_cleanup(&stack, 1);
	return r;
}

int trie_put(struct trie *t, t_key key, t_value value) 
{
	t_key cindex=0;
	int wasfull=0, wasempty=0;
	int pos, newpos;
	triestack stack=NULL;
	int tc, tp;
	int missbit, newbits;
	int current_node=t->head;

#ifdef DEBUG_TRIEOP
	if(debug) 
		printf("\n***************************  trie_insert\n");
#endif

	triestack_init(&stack);
	
	pos = 0;

	/* If we point to NULL, stop. Either the tree is empty and we should 
	 * just put a new leaf in if, or we have reached an empty child slot, 
	 * and we should just put our new leaf in that.
	 * If we point to a T_TNODE, check if it matches our key. Note that 
	 * a T_TNODE might be skipping any number of bits - its 'pos' need 
	 * not be the parent's 'pos'+'bits'!
	 *
	 * If it does match the current key, get pos/bits from it, extract 
	 * the index from our key, push the T_TNODE and walk the tree.
	 *
	 * If it doesn't, we have to replace it with a new T_TNODE.
	 *
	 * If we point to a T_LEAF, it might or might not have the same key 
	 * as we do. If it does, just change the value, update the T_LEAF's 
	 * value, and return it. 
	 * If it doesn't, we need to replace it with a T_TNODE.
	 */

        while (current_node != -1 && IS_TNODE(t, current_node)) {
		if (tkey_sub_equals(KEY(t, current_node), pos, POS(t, current_node) - pos, key))
		{
			triestack_push(stack, current_node, 0, 0);
			pos = POS(t, current_node) + BITS(t, current_node);
			current_node=CHILD(t, current_node, tkey_extract_bits(key, POS(t, current_node), BITS(t, current_node)));
		}
		else
			break;
        }

	/* Case 1: we have found a leaf and the key matches */

	if (current_node != -1 && IS_LEAF(t, current_node) && tkey_equals(KEY(t, current_node), key)) {
#ifdef DEBUG_TRIEOP
		if (debug)
			printf("Changing leaf %08x=%d to %d\n", KEY(t, current_node), (int)VALUE(t, current_node), value);
#endif
		VALUE(t, current_node) = value;
#ifdef TRIETRAV_SAFE
		t->revision++;
#endif
#ifdef DEBUG_TRIEOP
		if(debug) 
			printf("\n***************************  trie_insert done\n");
#endif
		triestack_cleanup(&stack, 1);
		return 0;
	}

	t->size++;

	triestack_pop(stack, &tp, NULL, NULL);
	if (tp != -1) {
		cindex = tkey_extract_bits(key, POS(t, tp), BITS(t, tp));
		tnode_get_fullempty(t, tp, cindex, &wasfull, &wasempty);
	}
	else
		cindex=-1;
		
	/* Case 2: we found nothing, and will just insert a new leaf */
	if (current_node == -1 || IS_FREE(t, current_node)) {
#ifdef DEBUG_TRIEOP
		if (debug)
			printf("Inserting new leaf for k=%08x v=%d\n", key, (int)value);
#endif
		if (tp == -1) {
#ifdef DEBUG_TRIEOP
			if (debug)
				printf("Leaf is first node\n");
#endif
			/* make a new single leaf */
			tc=trie_gethole(t, 1);

			TYPE(t, tc)=T_LEAF;
			KEY(t, tc)=key;
			VALUE(t, tc)=value;

#ifdef DEBUG_TRIEOP
			if (t->head != tc)
				printf("***setting head to %d\n", tc);
#endif
			t->head=tc;
#ifdef TRIETRAV_SAFE
			t->revision++;
#endif
#ifdef DEBUG_TRIEOP
			if(debug) 
				printf("\n***************************  trie_insert done\n");
#endif
			triestack_cleanup(&stack, 1);
			return 0;
		}
		else
		{
#ifdef DEBUG_TRIEOP
			if (debug)
				printf("Leaf will sit under %d\n", tp);
#endif
			tc = CHILD(t, tp, tkey_extract_bits(key, POS(t, tp), BITS(t, tp)));
			TYPE(t, tc)=T_LEAF;
			KEY(t, tc)=key;
			VALUE(t, tc)=value;
		}
	}

	/* Case 3: we found a T_LEAF or a T_TNODE and the key doesn't match. */
	else {
		int tmpc;
		int newleaf;
		/* Add a new tnode here */
#ifdef DEBUG_TRIEOP
		if (debug)
			printf("Adding a new tnode under %d for %d and our k=%08x/v=%d leaf\n", tp, current_node, key, (int)value);
#endif
		if (tp != -1)
			pos=POS(t, tp) + BITS(t, tp);
		else
			pos=0;

		tc = current_node;

		newpos = tkey_mismatch(key, pos, KEY(t, tc));
		newbits = 1;
		missbit=tkey_extract_bits(key, newpos, 1);

		tmpc=trie_gethole(t, 2);

		memcpy(&(NODE(t, tmpc+1-missbit)), &(NODE(t, tc)), sizeof(struct tnode));
#ifdef DEBUG_TRIEOP
		if (debug)
			printf("Children are at %d (old %d) and %d\n", tmpc+1-missbit, tc, tmpc+missbit);
#endif
		
		TYPE(t, tc)=T_TNODE;
		POS(t, tc)=newpos;
		BITS(t, tc)=newbits;
		NODE(t, tc).full_children=0;
		NODE(t, tc).empty_children=2;
		CHILDREN(t, tc)=tmpc;

		newleaf=CHILD(t, tc, missbit);
		TYPE(t, newleaf)=T_LEAF;
		KEY(t, newleaf)=key;
		VALUE(t, newleaf)=value;
		tnode_update_fullempty(t, tc, 1-missbit, 0, 1);
		tnode_update_fullempty(t, tc, missbit, 0, 1);
	}

	if (tp != -1)
		tnode_update_fullempty(t, tp, cindex, wasfull, wasempty);
	
	/* Rebalance the trie */

	while (tp != -1) {
		if (tc != -1 && IS_TNODE(t, tc)) {
			tnode_resize(t, tp, tc);
		}
		tc = tp;
		triestack_pop(stack, &tp, NULL, NULL);
	}

	if (tc != -1 && IS_TNODE(t, tc)) {
		tnode_resize(t, tp, tc);
	}
#ifdef DEBUG_TRIEOP
	if (t->head != tc)
		printf("***setting head to %d\n", tc);
#endif
	t->head=tc;

#ifdef TRIETRAV_SAFE
	t->revision++;
#endif
#ifdef DEBUG_TRIEOP
	if(debug) 
		printf("\n***************************  trie_insert done\n");
#endif
	return 0;
}

int trietrav_init(trietrav_handle *h, struct trie *t, int flags)
{
	(*h)=ALLOC(sizeof(struct trietrav_handle_s));
	if (!(*h))
		return 0;
	memset((*h), 0, sizeof(struct trietrav_handle_s));
	(*h)->t=t;
	triestack_init(&((*h)->stack));
#ifdef TRIETRAV_SAFE
	(*h)->trie_revision=t->revision;
	(*h)->lastkey=0;
#endif
	(*h)->flags=flags;
	(*h)->current_tn=-1;
	return 1;
}

void trietrav_cleanup(trietrav_handle *h)
{
	if (!(*h))
		return;
	triestack_cleanup(&((*h)->stack), 1);
	FREE(*h);
	(*h)=NULL;
}

int trietrav_next(trietrav_handle *h, t_key *k, t_value *v, int *depth)
{
	struct trie *t;
#ifdef TRIETRAV_SAFE
	int re_search=0;
	t_key lastkey=0;
#endif
	if (!(*h))
		return 0;

	t=(*h)->t;
#ifdef TRIETRAV_SAFE
	if ((*h)->trie_revision != t->revision)
	{
		lastkey=(*h)->lastkey;
		int flags=(*h)->flags;
		trietrav_cleanup(h);
		trietrav_init(h, t, flags);
		re_search=1;
	}
#endif
	if (((*h)->current_tn)==-1)
	{
		if (t->head == -1)
		{
			trietrav_cleanup(h);
			return 0;
		}
		else if (IS_LEAF(t, t->head))
		{
#ifdef TRIETRAV_SAFE
			if (re_search==0 || KEY(t, t->head) > lastkey)
			{
#endif
				(*k)=KEY(t, t->head);
				(*v)=VALUE(t, t->head);
				if (depth) (*depth)=0;
				trietrav_cleanup(h);
				return 1;
#ifdef TRIETRAV_SAFE
			}
			else
			{
				trietrav_cleanup(h);
				return 0;
			}
#endif
		}
		else
		{
			(*h)->current_tn=t->head;
			(*h)->current_index=0;
			(*h)->depth=0;
		}
	}
	while (1)
	{
		while ((*h)->current_index >= NCHILDREN(t, (*h)->current_tn))
		{
			if (triestack_pop((*h)->stack, &((*h)->current_tn), &((*h)->current_index), NULL)==-1)
			{
				trietrav_cleanup(h);
				return 0;
			}
			else
			{
				(*h)->current_index++;
				(*h)->depth--;
			}
		}
		if (IS_FREE(t, CHILD(t, (*h)->current_tn, (*h)->current_index))) (*h)->current_index++;
		else if (IS_LEAF(t, CHILD(t, (*h)->current_tn, (*h)->current_index)))
		{
			int ind=(*h)->current_index;
			(*h)->current_index++;
#ifdef TRIETRAV_SAFE
			if (re_search==0 || KEY(t, CHILD(t, (*h)->current_tn, ind)) > lastkey)
			{
				(*h)->lastkey=KEY(t, CHILD(t, (*h)->current_tn, ind));
#endif
				(*k)=KEY(t, CHILD(t, (*h)->current_tn, ind));
				(*v)=VALUE(t, CHILD(t, (*h)->current_tn, ind));
				if (depth) (*depth)=(*h)->depth;
				return 1;
#ifdef TRIETRAV_SAFE
			}
#endif

		}
		else if (IS_TNODE(t, CHILD(t, (*h)->current_tn, (*h)->current_index)))
		{
			triestack_push((*h)->stack, (*h)->current_tn, (*h)->current_index, 0);
			(*h)->current_tn=CHILD(t, (*h)->current_tn, (*h)->current_index);
			(*h)->current_index=0;
			(*h)->depth++;
		}
	}
}

struct trie_stat *trie_stat_new(void)
{
	struct trie_stat *s = ALLOC(sizeof(struct trie_stat));
	int i;
	
	if(s) {
		s->totDepth = 0;
		s->maxDepth = 0;
		s->internalNodes = 0;
		s->leaves = 0;
		s->nullPointers = 0;
				
		for(i=0; i<= MAX_BITS; i++)
			s->nodeSizes[i] = 0;
	}
	return s;
}    
    
void trie_collect_stat(struct trie *t, int node, int depth, struct trie_stat *s) 
{
        if (IS_FREE(t, node)) 
		s->nullPointers++;
	else if (IS_LEAF(t, node)) {

		if (depth > s->maxDepth)
			s->maxDepth = depth;
		s->totDepth += depth;
		s->leaves++;
        } else {
		int i;
		
		s->internalNodes++;
		s->nodeSizes[BITS(t, node)]++;
		for (i = 0; i < NCHILDREN(t, node); i++)
			trie_collect_stat(t, CHILD(t, node, i), depth + 1, s);
	}
}


/*
 * Return a string displaying statistics about the trie.
 */

void trie_print_stat(struct trie *t) 
{
        int bytes = 0; /* How many bytes are used, a ref is 4 bytes */
	int i, max, pointers;

        struct trie_stat *stat = trie_stat_new();
        trie_collect_stat(t, t->head, 0, stat);

	printf("Aver depth: %6.2f\n", (float) stat->totDepth / stat->leaves);
        printf("Max depth: %4d\n", stat->maxDepth);
        printf("Leaves: %d\n", stat->leaves);

        bytes += sizeof(struct tnode) * stat->leaves;
        printf("Internal nodes: %d\n", stat->internalNodes);

        bytes += sizeof(struct tnode) * stat->internalNodes;

	max = MAX_BITS;

        while (max >= 0 && stat->nodeSizes[max] == 0)
		max--;
        pointers = 0;

        for (i = 1; i <= max; i++) 
		if (stat->nodeSizes[i] != 0) {
			printf("  %d: %d",  i, stat->nodeSizes[i]);
			pointers += (1<<i) * stat->nodeSizes[i];
		}
        printf("\n");
        printf("Pointers: %d\n", pointers);
        bytes += sizeof(struct tnode *) * pointers;
        printf("Null ptrs: %d\n", stat->nullPointers);
        printf("Total size: %d  kB\n", bytes / 1024);
        printf("Actual size: %ld  kB\n", (long)(t->allocsz*sizeof(struct tnode) / 1024));
}
 

void trie_sanity_check(struct trie *t, int node, int depth) 
{
	int i;

        if (IS_FREE(t, node)); 
	else if (IS_LEAF(t, node)) {
		return;
        } else {
		for (i = 0; i < NCHILDREN(t, node); i++){
			trie_sanity_check(t, CHILD(t, node, i), depth + 1);
		}
	}
}

void putspace(int n)
{
	while (n--) printf(" ");
}

void printbin(unsigned int v, int bits)
{
	while (bits--)
		printf("%s", (v & (1<<bits))?"1":"0");
}

void printnode(int indent, struct trie *t, int node, int pend, int cindex, int bits)
{
	putspace(indent);
	if (IS_LEAF(t, node))
		printf("|");
	else
		printf("+");
	if (bits) {
		printf("%d/", cindex);
		printbin(cindex, bits);
		printf(": ");
	}
	else
		printf("<root>: ");
#if 0
	printf("%c:%d key=%08x\n", IS_LEAF(t, node)?'L':'N', node, KEY(t, node));
#else
	printf("%c:%d ", IS_LEAF(t, node)?'L':'N', node);
	if (IS_LEAF(t, node))
	  printf("key=%d.%d.%d.%d\n",
		  KEY(t, node) >> 24, (KEY(t, node) >> 16) % 256, (KEY(t, node) >> 8) % 256, KEY(t, node) % 256);
	else {
	  unsigned int pref=KEY(t, node) & TKEY_GET_MASK(0, POS(t, node));
	  printf("key=%d.%d.%d.%d/%d\n",
		  pref >> 24, (pref >> 16) % 256, (pref >> 8) % 256, pref % 256, POS(t, node));
	}
#endif
	if (IS_LEAF(t, node)) {
		putspace(indent); printf("|    {v=%p}\n", VALUE(t, node));;
	}
	else if (IS_TNODE(t, node)) {
		putspace(indent); printf("|    ");
		printf("{key prefix=%08x/", KEY(t, node)&TKEY_GET_MASK(0, POS(t, node)));
		printbin(tkey_extract_bits(KEY(t, node), 0, POS(t, node)), POS(t, node));
		printf("}\n");
		putspace(indent); printf("|    ");
		printf("{pos=%d", POS(t, node));
		printf(" (skip=%d bits)", POS(t, node) - pend);
		printf(" bits=%d (%u children)}\n", BITS(t, node), NCHILDREN(t, node));
		putspace(indent); printf("|    ");
		printf("{empty=%u full=%u}\n", NODE(t, node).empty_children, NODE(t, node).full_children);
	}
}

void trie_dump(struct trie *t, int node)
{
	int cindex=0;
	int indent=1;
	int pend=0;
	triestack stack=NULL;
	triestack_init(&stack);

	if (node!=-1 && !IS_FREE(t, node)) {
		printnode(indent, t, node, pend, cindex, 0);
		if (IS_TNODE(t, node)) {
			pend=POS(t, node) + BITS(t, node);
			putspace(indent); printf("\\--\n");
			indent+=3;
			while (node!=-1 && !IS_FREE(t, node) && cindex < NCHILDREN(t, node)) {
				int c=CHILD(t, node, cindex);
				if (c!=-1 && !IS_FREE(t, c)) {
					
					/* Got a child */

					printnode(indent, t, c, pend, cindex, BITS(t, node));
					if (IS_LEAF(t, c)) cindex++;
					else {
						/* 
						 * New tnode 
						 * push on stack and decend one level 
						 */

						triestack_push(stack, node, cindex, 0);
						node=c;
						pend=POS(t,node) +  BITS(t, node);
						putspace(indent); printf("\\--\n");
						indent+=3;
						cindex=0;
					}
				}
				else cindex++;

				/*
				 * Test if we are done 
				 */
				
				while (cindex >= NCHILDREN(t, node)) {

					/*
					 * Move upwards and test for root
					 * pop off all traversed  nodes
					 */

					if ((triestack_pop(stack,&node, &cindex, NULL))==-1) {
						break;
					}
					else {
						cindex++;
						pend=POS(t, node) + BITS(t, node);
						indent-=3;
					}
				}
			}
		}
		else
			node=-1;
	}
	triestack_cleanup(&stack, 1);
}

#ifdef HAVE_VARLIST_H
#include "varlist.h"

void putspace_s(char *s, int n)
{
	while (n--)
		strcat(s, " ");
}

void printbin_s(char *s, unsigned int v, int bits)
{
	while (bits--)
		strcat(s, (v & (1<<bits))?"1":"0");
}

void printnode_nl(namelist *v, int indent, struct trie *t, int node, int pend, int cindex, int bits)
{
	char linebuf[1024];
	linebuf[0]='\0';
	if (indent>100)
		indent=100;
	putspace_s(linebuf, indent);
	if (IS_LEAF(t, node))
		strcat(linebuf, "|");
	else
		strcat(linebuf, "+");
	if (bits) {
		sprintf(linebuf+strlen(linebuf), "%d/", cindex);
		printbin_s(linebuf, cindex, bits);
		strcat(linebuf, ": ");
	}
	else
		strcat(linebuf, "<root>: ");
#if 0
	sprintf(linebuf+strlen(linebuf), "%c:%d key=%08x\n", IS_LEAF(t, node)?'L':'N', node, KEY(t, node));
#else
	sprintf(linebuf+strlen(linebuf), "%c:%d ", IS_LEAF(t, node)?'L':'N', node);
	if (IS_LEAF(t, node))
	  sprintf(linebuf+strlen(linebuf), "key=%d.%d.%d.%d",
		  KEY(t, node) >> 24, (KEY(t, node) >> 16) % 256, (KEY(t, node) >> 8) % 256, KEY(t, node) % 256);
	else {
	  unsigned int pref=KEY(t, node) & TKEY_GET_MASK(0, POS(t, node));
	  sprintf(linebuf+strlen(linebuf), "key=%d.%d.%d.%d/%d",
		  pref >> 24, (pref >> 16) % 256, (pref >> 8) % 256, pref % 256, POS(t, node));
	}
#endif
	addname(v, linebuf);
	linebuf[0]='\0';
	if (IS_LEAF(t, node)) {
	  	putspace_s(linebuf, indent);
		sprintf(linebuf+strlen(linebuf), "|    {v=%p}", VALUE(t, node));
		addname(v, linebuf);
		linebuf[0]='\0';
	}
	else if (IS_TNODE(t, node)) {
	  	putspace_s(linebuf, indent);
		strcat(linebuf, "|    ");
		sprintf(linebuf+strlen(linebuf), "{key prefix=%08x/", KEY(t, node)&TKEY_GET_MASK(0, POS(t, node)));
		printbin_s(linebuf, tkey_extract_bits(KEY(t, node), 0, POS(t, node)), POS(t, node));
		strcat(linebuf, "}");
		addname(v, linebuf);
		linebuf[0]='\0';
		putspace_s(linebuf, indent);
		strcat(linebuf, "|    ");
		sprintf(linebuf+strlen(linebuf), "{pos=%d", POS(t, node));
		sprintf(linebuf+strlen(linebuf), " (skip=%d bits)", POS(t, node) - pend);
		sprintf(linebuf+strlen(linebuf), " bits=%d (%u children)}", BITS(t, node), NCHILDREN(t, node));
		addname(v, linebuf);
		linebuf[0]='\0';
		putspace_s(linebuf, indent);
		strcat(linebuf, "|    ");
		sprintf(linebuf+strlen(linebuf), "{empty=%u full=%u}", NODE(t, node).empty_children, NODE(t, node).full_children);
		addname(v, linebuf);
		linebuf[0]='\0';
	}
}

void trie_dump_nl(namelist *v, struct trie *t)
{
	int cindex=0;
	int indent=1;
	int pend=0;
	int node=t->head;
	char linebuf[1024];
	triestack my_stack=NULL;
	triestack_init(&my_stack);
	linebuf[0]='\0';
	if (node != -1 && !IS_FREE(t, node)) {
		printnode_nl(v, indent, t, node, pend, cindex, 0);
		if (IS_TNODE(t, node)) {
			pend = POS(t, node) + BITS(t, node);
			putspace_s(linebuf, indent);
			strcat(linebuf, "\\--");
			addname(v, linebuf);
			linebuf[0]='\0';
			indent+=3;
			while (node!=-1 && !IS_FREE(t, node) && cindex < NCHILDREN(t, node)) {
				int c=CHILD(t, node, cindex);
				if (c!=-1 && !IS_FREE(t, c)) {
					
					/* Got a child */

					printnode_nl(v, indent, t, c, pend, cindex, BITS(t, node));
					if (IS_LEAF(t, c)) cindex++;
					else {
						/* 
						 * New tnode 
						 * push on stack and decend one level 
						 */

						triestack_push(my_stack, node, cindex, 0);
						node=c;
						pend=POS(t,node) +  BITS(t, node);
						putspace_s(linebuf, indent);
						strcat(linebuf, "\\--");
						addname(v, linebuf);
						linebuf[0]='\0';
						indent+=3;
						cindex=0;
					}
				}
				else cindex++;

				/*
				 * Test if we are done 
				 */
				
				while (cindex >= NCHILDREN(t, node)) {

					/*
					 * Move upwards and test for root
					 * pop off all traversed  nodes
					 */

					if ((triestack_pop(my_stack,&node, &cindex, NULL))==-1) {
						break;
					}
					else {
						cindex++;
						pend=POS(t, node) + BITS(t, node);
						indent-=3;
					}
				}
			}
		}
		else node=-1;
	}
	triestack_cleanup(&my_stack, 1);
}

#endif
