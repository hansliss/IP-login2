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

