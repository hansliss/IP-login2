int iptables_add_line(char *table, char *chain, struct in_addr *addr);
int iptables_delete_line(char *table, char *chain, struct in_addr *addr);
int iptables_add_block(char *table, char *chain, struct in_addr *addr);
int iptables_delete_block(char *table, char *chain, struct in_addr *addr);
int iptables_flush_chain(char *table, char *chain);
int iptables_create_chain(char *table, char *chain);
void iptables_init(void);

