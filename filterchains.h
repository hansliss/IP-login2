#ifndef _FILTERCHAINS_H
#define _FILTERCHAINS_H

#include <netinet/in.h>

/*
  Flush the chain calles 'chain' (in), removing all rules from it.
  */
void fchain_flush(char *chain);

/*
  Create a new chain called 'chain' (in) or fail silently if it already
  exists.
  */
void fchain_create(char *chain);

/*
  Add a rule to the chain 'chain' (in) permitting all traffic from/to the
  address 'address' (in).
  */
void fchain_addrule(struct in_addr address, char *spec);

/*
  Delete a rule from the chain 'chain' (in), permitting all traffic from/to
  the address 'address' (in) or fail silently if none exists.
  */
void fchain_delrule(struct in_addr address, char *spec);

/*
  Flush all the chains for which we consider ourselves responsible.
  */
void fchain_unloadall();

typedef struct counternode_s
{
  struct in_addr address;
  u_int64_t rxcounter;
  u_int64_t txcounter;
  struct counternode_s *next;
} *counternode;

/*
  Retrieve RX and TX byte counters
  */
int fchain_getcounters(char *spec, counternode requested_counters);

/*
  Initialize the 'filterchains' system. Well, set used_chains to NULL..
  */
void fchain_init();

#endif
