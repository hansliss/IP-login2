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
