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
void fchain_addrule(struct in_addr address, char *chain);

/*
  Delete a rule from the chain 'chain' (in), permitting all traffic from/to
  the address 'address' (in) or fail silently if none exists.
  */
void fchain_delrule(struct in_addr address, char *chain);

/*
  Add a blocking TCP rule to the chain 'chain' (in) blocking all tcp traffic from the
  address 'address' (in).
  */
void fchain_addblock(struct in_addr address, char *chain);

/*
  Delete a blocking rule from the chain 'chain' (in), for the
  address 'address' (in) or fail silently if none exists.
  */
void fchain_delblock(struct in_addr address, char *chain);

/*
  Flush all the chains for which we consider ourselves responsible.
  */
void fchain_unloadall();

/*
  Initialize the 'filterchains' system. Well, set used_chains to NULL..
  */
void fchain_init();





