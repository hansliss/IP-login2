/*
  Determine the interface index and source address to use for
  outgoing packet to a given destination.

  Parameters:
  'dest' (in): The destination we are looking for
  'src' (out): The source address to use - preallocated!

  Returns the interface index or <0 if an error has occured.

  syslog() is used here so openlog() before calling this
  */
int find_interface(struct in_addr *dest, struct in_addr *src);

/*
  Find out which type this user is.
  If 'src' (out) is non-NULL it will be filled with an appropriate source
  address for this 'dst' (in).

  Returns the user type (see usernode.h) or USER_TYPE_NONE if
  it fails.

  syslog() is used here so openlog() before calling this
 */
int determine_type(struct in_addr *dst, struct in_addr *src);

