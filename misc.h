#include "config.h"

/* Get the current RSS (Resident Segment Size) from the proc file system
   and return it */
int getRSS();

/* Get the current 'vsize' (virtual memory size) from the proc file system
   and return it */
unsigned long getvsize();

/* Recalculate timing parameters */
void recalc(struct pingconfig *pingconf, int logout_timeout, int number_of_users);
