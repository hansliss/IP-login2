/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 *
 *   Hans Liss <hans.liss@its.uu.se>  Uppsala Universitet
 *
 *   The file LICENSE must accompany this package when redistributed.
 *   Please refer to it for specific acknowledgements.
 *
 */

#include "filterchains.h"

int iptables_read_counters(char *table, char *chain, counternode counters);
int iptables_add_line(char *table,
		      char *chain,
		      struct in_addr *saddr,
		      struct in_addr *smsk,
		      struct in_addr *daddr,
		      struct in_addr *dmsk,
		      char *target);
int iptables_delete_line(char *table,
		      char *chain,
		      struct in_addr *saddr,
		      struct in_addr *smsk,
		      struct in_addr *daddr,
		      struct in_addr *dmsk,
		      char *target);
int iptables_flush_chain(char *table, char *chain);
int iptables_create_chain(char *table, char *chain);
void iptables_init(void);
