#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <iptables.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>

#include "filterchains.h"

#ifndef IPT_LIB_DIR
#define IPT_LIB_DIR "/usr/lib/iptables"
#endif

const char *program_version=IPTVERSION;
const char *program_name="iplogin2";

/* Keeping track of external matches and targets: linked lists.  */
struct iptables_match *iptables_matches = NULL;
struct iptables_target *iptables_targets = NULL;

void free_handle(iptc_handle_t *h)
{
  if (*h)
    free(*h);
  (*h)=NULL;
}

struct iptables_match *find_match(const char *name, enum ipt_tryload tryload)
{
  struct iptables_match *ptr;

  for (ptr = iptables_matches; ptr; ptr = ptr->next)
    {
      if (strcmp(name, ptr->name) == 0)
	break;
    }

#ifndef NO_SHARED_LIBS
	if (!ptr && tryload != DONT_LOAD) {
		char path[sizeof(IPT_LIB_DIR) + sizeof("/libipt_.so")
			 + strlen(name)];
		sprintf(path, IPT_LIB_DIR "/libipt_%s.so", name);
		if (dlopen(path, RTLD_NOW)) {
			/* Found library.  If it didn't register itself,
			   maybe they specified target as match. */
			ptr = find_match(name, DONT_LOAD);

			if (!ptr)
			  return NULL
		} else if (tryload == LOAD_MUST_SUCCEED)
		  return NULL
	}
#else
	if (ptr && !ptr->loaded) {
		if (tryload != DONT_LOAD)
			ptr->loaded = 1;
		else
			ptr = NULL;
	}
#endif

  if (ptr)
    ptr->used = 1;

  return ptr;
}

void register_match(struct iptables_match *me)
{
  struct iptables_match **i;

  if (strcmp(me->version, program_version) != 0)
    {
      syslog(LOG_ERR, "%s: match `%s' v%s (I'm v%s).\n",
	      program_name, me->name, me->version, program_version);
      return;
    }

  if (find_match(me->name, DONT_LOAD))
    {
      syslog(LOG_ERR, "%s: match `%s' already registered.\n",
	      program_name, me->name);
      return;
    }

  if (me->size != IPT_ALIGN(me->size))
    {
      syslog(LOG_ERR, "%s: match `%s' has invalid size %u.\n",
	      program_name, me->name, me->size);
      return;
    }

  /* Append to list. */
  for (i = &iptables_matches; *i; i = &(*i)->next);
  me->next = NULL;
  *i = me;

  me->m = NULL;
  me->mflags = 0;
}

struct iptables_target *find_target(const char *name, enum ipt_tryload tryload)
{
  struct iptables_target *ptr;

  /* Standard target? */
  if (strcmp(name, "") == 0
      || strcmp(name, IPTC_LABEL_ACCEPT) == 0
      || strcmp(name, IPTC_LABEL_DROP) == 0
      || strcmp(name, IPTC_LABEL_QUEUE) == 0
      || strcmp(name, IPTC_LABEL_RETURN) == 0)
    name = "standard";

  for (ptr = iptables_targets; ptr; ptr = ptr->next)
    {
      if (strcmp(name, ptr->name) == 0)
	break;
    }

#ifndef NO_SHARED_LIBS
	if (!ptr && tryload != DONT_LOAD) {
		char path[sizeof(IPT_LIB_DIR) + sizeof("/libipt_.so")
			 + strlen(name)];
		sprintf(path, IPT_LIB_DIR "/libipt_%s.so", name);
		if (dlopen(path, RTLD_NOW)) {
			/* Found library.  If it didn't register itself,
			   maybe they specified match as a target. */
			ptr = find_target(name, DONT_LOAD);
			if (!ptr)
			  return NULL;
		} else if (tryload == LOAD_MUST_SUCCEED)
		  return NULL;
	}
#else
	if (ptr && !ptr->loaded) {
		if (tryload != DONT_LOAD)
			ptr->loaded = 1;
		else
			ptr = NULL;
	}
#endif

  if (ptr)
    ptr->used = 1;

  return ptr;
}

void register_target(struct iptables_target *me)
{
  if (strcmp(me->version, program_version) != 0)
    {
      syslog(LOG_ERR, "%s: target `%s' v%s (I'm v%s).\n",
	      program_name, me->name, me->version, program_version);
      return;
    }

  if (find_target(me->name, DONT_LOAD))
    {
      syslog(LOG_ERR, "%s: target `%s' already registered.\n",
	      program_name, me->name);
      return;
    }

  if (me->size != IPT_ALIGN(me->size))
    {
      syslog(LOG_ERR, "%s: target `%s' has invalid size %u.\n",
	      program_name, me->name, me->size);
      return;
    }

  /* Prepend to list. */
  me->next = iptables_targets;
  iptables_targets = me;
  me->t = NULL;
  me->tflags = 0;
}

static struct ipt_entry *generate_entry(const struct ipt_entry *fw,
					struct iptables_match *matches,
					struct ipt_entry_target *target)
{
  unsigned int size;
  struct iptables_match *m;
  struct ipt_entry *e;

  size = sizeof(struct ipt_entry);
  for (m = matches; m; m = m->next)
    {
      if (m->used)
	size += m->m->u.match_size;
    }

  if (!(e = (struct ipt_entry *)malloc(size + target->u.target_size)))
    return NULL;
  *e = *fw;
  e->target_offset = size;
  e->next_offset = size + target->u.target_size;

  size = 0;
  for (m = matches; m; m = m->next)
    {
      if (m->used)
	{
	  memcpy(e->elems + size, m->m, m->m->u.match_size);
	  size += m->m->u.match_size;
	}
    }
  memcpy(e->elems + size, target, target->u.target_size);

  return e;
}

static unsigned char *make_delete_mask(struct ipt_entry *fw)
{
  /* Establish mask for comparison */
  unsigned int size;
  struct iptables_match *m;
  unsigned char *mask, *mptr;

  size = sizeof(struct ipt_entry);
  for (m = iptables_matches; m; m = m->next)
    {
      if (!m->used)
	continue;

      size += IPT_ALIGN(sizeof(struct ipt_entry_match)) + m->size;
    }

  mask = calloc(1, size
		+ IPT_ALIGN(sizeof(struct ipt_entry_target))
		+ iptables_targets->size);

  memset(mask, 0xFF, sizeof(struct ipt_entry));
  mptr = mask + sizeof(struct ipt_entry);

  for (m = iptables_matches; m; m = m->next)
    {
      if (!m->used)
	continue;

      memset(mptr, 0xFF,
	     IPT_ALIGN(sizeof(struct ipt_entry_match))
	     + m->userspacesize);
      mptr += IPT_ALIGN(sizeof(struct ipt_entry_match)) + m->size;
    }

  memset(mptr, 0xFF,
	 IPT_ALIGN(sizeof(struct ipt_entry_target))
	 + iptables_targets->userspacesize);

  return mask;
}

int iptables_read_counters(char *table, char *chain, counternode counters)
{
  iptc_handle_t handle=NULL;
  const struct ipt_entry *this;
  counternode tmpcnt;
  handle = iptc_init(table);
  if (!handle)
    {
      syslog(LOG_ERR,"iptc_init() failed\n");
      return 0;
    }

  this = iptc_first_rule(chain, &handle);
  while (this)
    {
      if ((this->ip.src.s_addr == 0) &&
	  (this->ip.smsk.s_addr == 0) &&
	  (this->ip.dmsk.s_addr == 0xFFFFFFFFL) &&
	  !(this->ip.invflags & IPT_INV_DSTIP))   /* RX counter */
	{
	  tmpcnt=counters;
	  while (tmpcnt)
	    {
	      if (!memcmp(&(this->ip.dst.s_addr), &(tmpcnt->address), sizeof(tmpcnt->address)) &&
		  tmpcnt->rxcounter == 0)
		tmpcnt->rxcounter=this->counters.bcnt;
	      tmpcnt=tmpcnt->next;
	    }
	}
      else if ((this->ip.dst.s_addr == 0) &&
	       (this->ip.dmsk.s_addr == 0) &&
	       (this->ip.smsk.s_addr == 0xFFFFFFFFL) &&
	       !(this->ip.invflags & IPT_INV_SRCIP))   /* TX counter */
	{
	  tmpcnt=counters;
	  while (tmpcnt)
	    {
	      if (!memcmp(&(this->ip.src.s_addr), &(tmpcnt->address), sizeof(tmpcnt->address)) &&
		  tmpcnt->txcounter == 0)
		tmpcnt->txcounter=this->counters.bcnt;
	      tmpcnt=tmpcnt->next;
	    }
	}
      this = iptc_next_rule(this, &handle);
    }
  free_handle(&handle);
  return 1;
}

int iptables_add_delete_line(int type,
			     char *table,
			     char *chain,
			     struct in_addr *saddr,
			     struct in_addr *smsk,
			     struct in_addr *daddr,
			     struct in_addr *dmsk,
			     char *targetname)
{
  struct ipt_entry fw;
  struct iptables_target *target, *t;
  struct iptables_match *m;
  struct ipt_entry *e;
  iptc_handle_t handle=NULL;
  size_t size;
  int ret=0;
  unsigned char *mask;
  u_int16_t proto=0;

  memset(&fw, 0, sizeof(fw));
  fw.nfcache |= NFC_IP_SRC;

  handle = iptc_init(table);
  if (!handle)
    {
      syslog(LOG_ERR,"iptc_init() failed\n");
      return 0;
    }

  /* clear mflags in case do_command gets called a second time
   * (we clear the global list of all matches for security)*/

  for (m = iptables_matches; m; m = m->next)
    {
      m->mflags = 0;
      m->used = 0;
    }

  for (t = iptables_targets; t; t = t->next)
    {
      t->tflags = 0;
      t->used = 0;
    }

  if (!iptc_is_chain(targetname, handle))
    target = find_target(targetname, TRY_LOAD);
  else
    target = find_target(IPT_STANDARD_TARGET, LOAD_MUST_SUCCEED);

  if (!target)
    {
      syslog(LOG_ERR,"Target \"%s\" not found\n", targetname);
      return 0;
    }

  size = IPT_ALIGN(sizeof(struct ipt_entry_target)) + target->size;
  
  if (!(target->t = calloc(1, size)))
    {
      syslog(LOG_ERR,"calloc(): %m");
      return 0;
    }

  target->t->u.target_size = size;
  strcpy(target->t->u.user.name, targetname);
  target->init(target->t, &fw.nfcache);
  target->final_check(target->tflags);
  target->used=1;

  memcpy(&fw.ip.src, saddr, sizeof(struct in_addr));
  memcpy(&fw.ip.smsk, smsk, sizeof(struct in_addr));
  memcpy(&fw.ip.dst, daddr, sizeof(struct in_addr));
  memcpy(&fw.ip.dmsk, dmsk, sizeof(struct in_addr));
  fw.ip.proto=proto;
  e=NULL;

  switch(type)
    {
    case 1:
      if (!(e = generate_entry(&fw, iptables_matches, target->t)))
	{
	  free_handle(&handle);
	  syslog(LOG_ERR,"generate_entry() failed\n");
	  return 0;
	}

      ret = iptc_append_entry(chain, e, &handle);
      break;
    case 2:
      if (!(e = generate_entry(&fw, iptables_matches, target->t)))
	{
	  free_handle(&handle);
	  syslog(LOG_ERR,"generate_entry() failed\n");
	  return 0;
	}

      mask = make_delete_mask(&fw);
      ret = iptc_delete_entry(chain, e, mask, &handle);
      free(mask);
      break;
    }
  free(target->t);
  target->t=NULL;
  target->used=0;
  free(e);
  if (ret)
    ret = iptc_commit(&handle);
  free_handle(&handle);
  return ret;
}

int iptables_add_line(char *table,
		      char *chain,
		      struct in_addr *saddr,
		      struct in_addr *smsk,
		      struct in_addr *daddr,
		      struct in_addr *dmsk,
		      char *target)
{
  return iptables_add_delete_line(1,table,chain,saddr,smsk,daddr,dmsk,target);
}
 
int iptables_delete_line(char *table,
			 char *chain,
			 struct in_addr *saddr,
			 struct in_addr *smsk,
			 struct in_addr *daddr,
			 struct in_addr *dmsk,
			 char *target)
{
  return iptables_add_delete_line(2,table,chain,saddr,smsk,daddr,dmsk,target);
}

int iptables_flush_chain(char *table, char *chain)
{
  iptc_handle_t handle=NULL;
  int ret;
  handle = iptc_init(table);
  if (!handle)
    return 0;
  ret = iptc_flush_entries(chain, &handle);
  if (ret)
    ret = iptc_commit(&handle);
  free_handle(&handle);
  return ret;
}

int iptables_create_chain(char *table, char *chain)
{
  iptc_handle_t handle=NULL;
  int ret;
  handle = iptc_init(table);
  if (!handle)
    return 0;
  ret = iptc_create_chain(chain, &handle);
  if (ret)
    ret = iptc_commit(&handle);
  if (!handle)
    if (!(handle = iptc_init(table)))
      return 0;
  ret = iptc_zero_entries(chain, &handle);
  if (ret)
    ret = iptc_commit(&handle);
  free_handle(&handle);
  return ret;
}

void iptables_init()
{
#ifdef NO_SHARED_LIBS
  init_extensions();
#endif
}


void
exit_error(enum exittype status, char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	fprintf(stderr, "%s v%s: ", program_name, program_version);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(status);
}

char *
addr_to_dotted(const struct in_addr *addrp)
{
	static char buf[20];
	const unsigned char *bytep;

	bytep = (const unsigned char *) &(addrp->s_addr);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#if 0
int
check_inverse(const char option[], int *invert)
{
        if (option && strcmp(option, "!") == 0) {
                if (*invert)
                        exit_error(PARAMETER_PROBLEM,
                                   "Multiple `!' flags not allowed");

                *invert = TRUE;
                return TRUE;
        }
        return FALSE;
}
#endif

struct in_addr *
dotted_to_addr(const char *dotted)
{
	static struct in_addr addr;
	unsigned char *addrp;
	char *p, *q;
	unsigned int onebyte;
	int i;
	char buf[20];

	/* copy dotted string, because we need to modify it */
	strncpy(buf, dotted, sizeof(buf) - 1);
	addrp = (unsigned char *) &(addr.s_addr);

	p = buf;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return (struct in_addr *) NULL;

		*q = '\0';
		if (string_to_number(p, 0, 255, &onebyte) == -1)
			return (struct in_addr *) NULL;

		addrp[i] = (unsigned char) onebyte;
		p = q + 1;
	}

	/* we've checked 3 bytes, now we check the last one */
	if (string_to_number(p, 0, 255, &onebyte) == -1)
		return (struct in_addr *) NULL;

	addrp[3] = (unsigned char) onebyte;

	return &addr;
}

int
string_to_number(const char *s, unsigned int min, unsigned int max,
		 unsigned int *ret)
{
	long number;
	char *end;

	/* Handle hex, octal, etc. */
	errno = 0;
	number = strtol(s, &end, 0);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (errno != ERANGE && min <= number && number <= max) {
			*ret = number;
			return 0;
		}
	}
	return -1;
}

