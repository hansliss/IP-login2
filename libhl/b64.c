#define B64_CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define B64_REVERSE(c)  ((((c) >= 'A') && ((c) <= 'Z'))?(c)-'A':\
(((((c) >= 'a') && ((c) <= 'z')))?(c)-'a'+26:\
((((c) >= '0') && ((c) <= '9'))?(c)-'0'+52:\
(((c)=='+')?62:\
((c) == '/')?63:\
65))))
#define PAD '='

int b64_encode(unsigned char *indata, int indatalen, char *result, int reslen)
{
  unsigned char A,B,C,D;
  int i, j;

  for (i=0, j=0; (i < (indatalen-2)) && (j < (reslen-4)); i+=3, j+=4)
    {
      A=(indata[i] & 0xFC) >> 2;
      B=((indata[i] & 0x03) << 4) | ((indata[i+1] & 0xF0) >> 4);
      C=((indata[i+1] & 0x0F) << 2) | ((indata[i+2] & 0xC0) >> 6);
      D=(indata[i+2] & 0x3F);
      result[j]=B64_CHARSET[A];
      result[j+1]=B64_CHARSET[B];
      result[j+2]=B64_CHARSET[C];
      result[j+3]=B64_CHARSET[D];
    }

  if (j >= reslen)
    return 0;

  result[j]='\0';

  if (i<indatalen)
    {
      if (j >= (reslen-4))
	return 0;
      A=(indata[i] & 0xFC) >> 2;
      B=(indata[i] & 0x03) << 4;
      result[j]=B64_CHARSET[A];
      if (i<(indatalen-1))
	{
	  B |= ((indata[i+1] & 0xF0) >> 4);
	  C = (indata[i+1] & 0x0F) << 2;
	  result[j+2]=B64_CHARSET[C];
	}
      else
	result[j+2]=PAD;
      result[j+1]=B64_CHARSET[B];
      result[j+3]=PAD;
    }
  result[j+4]='\0';
  return (j+4);
}

int b64_decode(unsigned char *indata, int indatalen, char *result, int reslen)
{
  int i, j, r=0;
  unsigned char A,B,C,D,a,b,c;
  if ((indatalen % 4)!=0)
    return 0;
  if (reslen < (3 * indatalen / 4))
    return 0;
  for (i=0, j=0; (i < (indatalen - 3)) && (j < reslen); i+=4, j+=3)
    {
      A=B64_REVERSE(indata[i]);
      B=B64_REVERSE(indata[i+1]);
      C=B64_REVERSE(indata[i+2]);
      D=B64_REVERSE(indata[i+3]);
      if (A == 65)
	return 0;
      a=A << 2;
      if (B != 65)
	{
	  a |= (B & 0x30) >> 4;
	  b = (B & 0x0F) << 4;
	  if (C != 65)
	    {
	      b |= (C & 0x3C) >> 2;
	      c = (C & 0x03) << 6;
	      if (D != 65)
		{
		  c |= D;
		  if (j < reslen-2)
		    {
		      result[j+2]=c;
		      r=j+3;
		    }
		  else
		    r=0;
		}
	      else
		r=j+2;
	      if (j < reslen-1)
		result[j+1]=b;
	      else
		r=0;
	    }
	  else
	    r=j+1;
	  result[j]=a;
	}
      else
	r=j;
    }
  if (i < (indatalen - 3))
    return 0;
  result[r]='\0';
  return r;
}

