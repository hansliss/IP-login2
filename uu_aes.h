#ifndef _UU_AES_H
#define _UU_AES_H

int uu_aes_encrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize, unsigned char *ivin);
int uu_aes_decrypt(unsigned char *ctext, int ctextsize, unsigned char *key, int keysize, char *outbuf, int outbufsize);

#endif
