/*
  A structure for keeping track of a list of sockets and misc data
  for them.
  */

typedef struct socknode
{
  /* Interface index */
  int ifindex;

  /* Socket type - see usernode.h */
  int type;

  /* The socket's fd */
  int socket;

  /* Extra data for this socket */
  unsigned char data[1024];

  /* Link */
  struct socknode *next;
} *socketnode;
