void *acct_init(char *libname, char *progname);
int acct_cleanup(void *handle);
int acct_login(void *handle, char *account, char *session_id);
int acct_logout(void *handle, char *account, char *session_id);
char *acct_last_error(void);



