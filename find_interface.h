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
  Determine the interface index and source address to use for
  outgoing packet to a given destination.

  Parameters:
  'dest' (in): The destination we are looking for
  'src' (out): The source address to use - preallocated!

  'namebuf' (out): A buffer for the interface name - preallocated - or NULL.
  'namelen' (in): The size of the 'namebuf'

  Returns the interface index or <0 if an error has occured.

  syslog() is used here so openlog() before calling this
  */
int find_interface(struct in_addr *dest, struct in_addr *src, char *namebuf, int namelen);

/*
  Find out which type this user is.
  If 'src' (out) is non-NULL it will be filled with an appropriate source
  address for this 'dst' (in).

  Returns the user type (see usernode.h) or USER_TYPE_NONE if
  it fails.

  syslog() is used here so openlog() before calling this
 */
int determine_type(struct in_addr *dst, struct in_addr *src);

