#ifdef WIN32
extern void syslog(int s, const char *fmt, ...);
#define LOG_ERR 0
#define LOG_DEBUG 1
#define LOG_NOTICE 2
#define LOG_INFO 3
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <winsock2.h>
#include <io.h>
#else
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SOCKET int
#endif



/* Translate a dotted quad or a hostname to an IP address if
   possible. Return 0 if it fails, non-0 otherwise */
int makeaddress(char *name_or_ip, struct in_addr *res);

/* Translate a service name or port number (as a string) into an NBO
   integer. Return 0 on failure. */
int makeport(char *name_or_port);

