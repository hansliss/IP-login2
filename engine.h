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

#include "config.h"

/*
  The main loop. But you knew that.

  'command_server_socket' (in): Umm...the socket for the command server?
  */
int mainloop(struct config *conf, int command_server_socket);

