#ifndef USERNODE_H
#define USERNODE_H

#include <netinet/in.h>
#include <time.h>
#include <linux/if_arp.h>
#include <hl.h>

/************* List handling code **************/

typedef struct susernode
{
  /* The account name */
  char *account;

  /* User type - see above */
  int user_type;

  /*
    Address - used for both ping and arpping
    ****  This is the unique key for this list ****
   */
  struct in_addr address;

  /*
    Link layer address for ARP Ping
    */
  struct sockaddr_ll ll_address;
  int ll_address_set;

  /* The interface index for outgoing traffic for this user */
  int ifindex;

  /* The interface name for that interface */
  char ifname[32];

  /* The source address to use for this user */
  struct in_addr source_address;

  /* A list of iptables/ipchains chains which this address belong to */
  namelist filter_chains;

  /* How many packets have been missed by this node? */
  unsigned int missed;

  /* How many packets have been missed by this node? */
  unsigned int hits;

  /* When did we add this user? */
  time_t added;

  /* When did we send the last packet to this address? */
  time_t last_sent;
  time_t last_checked_send;

  /* When was the last STAT command for this address executed? */
  time_t last_stat;

  /* How many STAT commands below the mitigation threshold have we received? */
  int statmit_count;

  /* How long has this user's block been active? */
  time_t block_installed;

  /* When did we receive the last reply from this address? */
  time_t last_received;

  /* A 'session' id for use by external accounting packages
     like Radius */
  char session_id[17];

  /* RX and TX counters */
  u_int64_t rxcounter, txcounter;

  /* TX and TX kbits/s */
  unsigned int rxkbps, txkbps;

  /* Link to next */
  struct susernode *next;
} *usernode;

/*
  Add a new user to the list 'l' (in/out).
  Parameters:
  'l' (in/out): The list to which this new node is to be added
  'account' (in): The account name
  'user_type' (in): The user type - See above
  'address' (in): The IP adress of this user
  'ifindex' (in): The interface index to be used for this user
  'ifname' (in): The name of that interface
  'source' (in): The source IP address to be used for traffic to this user
  'chains' (in): A list of filter chain names for this user
  'added' (in): The time at which this user was added.

  Returns the new usernode that was added to the list.

  Note: This function does not check for duplicates. If a duplicate
  is created, the first one in the list will override any others.
  */
usernode addUser(usernode *l, char *account, char *session_id, int user_type,
		       struct in_addr *address, int ifindex, char *ifname,
		       struct in_addr *source, namelist chains, time_t added,
		       void *accounting_handle);

/*
  Find a user with the address 'address' (in) in the list 'l' (in).

  Returns the usernode or NULL if not found.
  */
usernode findUser(usernode l, struct in_addr *address);

/*
  Find a user with the account name 'account' (in) in the list 'l' (in).

  Returns the usernode or NULL if not found.
  */
usernode findUser_account(usernode l, char *account);

/*
  Delete a user node in list 'l' (in/out) with address 'address' (in).
 */
void delUser(usernode *l, struct in_addr *address, void *accounting_handle);

/*
  Release all memory occupied by the list 'l' (in/out) and set it to
  NULL.
  */
void freeUserList(usernode *l, void *accounting_handle);

#endif
