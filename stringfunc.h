#ifndef STRINGFUNC_H
#define STRINGFUNC_H

/* Remove junk characters from a string for logging and stuff */
void dejunkifyforlog(char *s);

/*
  Remove all blanks at the beginning and end of the string 'string' (in/out).
  */
void cleanupstring(char *string);

/*
  Chop off all whitespace characters (including newline characters etc)
  from the end of the string 'string' (in/out).
  */
void chop(char *string);

/* Base64 encode/decode */
int b64_encode(unsigned char *indata, int indatalen, char *result, int reslen);
int b64_decode(unsigned char *indata, int indatalen, char *result, int reslen);

#endif
