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

/* Get the current RSS (Resident Segment Size) from the proc file system
   and return it */
int getRSS();

/* Get the current 'vsize' (virtual memory size) from the proc file system
   and return it */
unsigned long getvsize();

/* Recalculate timing parameters */
void recalc(struct pingconfig *pingconf, int logout_timeout, int number_of_users);
