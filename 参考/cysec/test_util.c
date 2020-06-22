#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

#if !defined(SAFE_FREE)
#define SAFE_FREE(x) do{ if(x) free(x); x=NULL; }while(0)
#endif

#if !defined(s_assert)
#define s_assert(v, fmt, arg...) \
	do { \
		if (!(v)) { \
			printf("[ASSERT] %s:%d " fmt "\n", __FILE__, __LINE__, ##arg); \
		} \
} while(0)
#endif

#define KPOOL_PATH "./kpool"

unsigned char* FILE_getcontent(const char* fname, size_t* len) {
  FILE *fp = NULL;
  unsigned char* r = NULL;
  long l;
  
  if ((fp = fopen(fname,"r"))==NULL) {
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  l = ftell(fp);
  if (l > 0) {
    r = (unsigned char *)malloc(l + 1);
    fseek(fp, 0, SEEK_SET);
    if (fread(r, l, 1, fp) <= 0) {
			free(r);
			r = NULL;
			l = 0;
			goto end;
		}
		r[l] = '\0';
  }
	
end:
	if (len != NULL) {
  	*len = l ;
	}
  fclose(fp);
  return r;
}

int FILE_putcontent(const unsigned char *in, size_t ilen, const char *fname) {
	FILE *fp = NULL;
	size_t wlen = 0;

	if ((fp = fopen(fname,"w"))==NULL) {
		return -1;
  	} 

  	if(in && ilen > 0){
  		wlen = fwrite(in, 1, ilen, fp);
  		if(wlen != ilen){
  			fclose(fp);
  			return -1;
  		}
  	}

  	fclose(fp);
  	return 0;
}

void fillbuf(unsigned char* buf, size_t blen) {
	size_t n;
	for (n = 0; n < blen; n ++) {
		buf[n] = (n & 0xff);
	}
}

void dumpcrt(X509CRT_PCTX x) {
	if (!x) {
		printf("crt is NULL! xxxxxxxxxxxxxxxxxxxx \n");
		return;
	}
	printf("+++++ subject=[%s] issuer=[%s] sn=[%s] notbefore=[%s] notafter=[%s]\n", 
			x509crt_get_subject(x),
			x509crt_get_issuer(x),
			x509crt_get_sn(x),
			x509crt_get_notbefore(x),
			x509crt_get_notafter(x));
}

void dumpkey(PKEY_PCTX x) {
	if (!x) {
		printf("key is NULL! xxxxxxxxxxxxxxxxxxxx \n");
		return;
	}
	printf("----- keytype=[%s] bits=[%d] private=[%d]\n", 
		pkey_is_rsa(x) ? "rsa" : (pkey_is_sm2(x) ? "sm2" : (pkey_is_ecc(x) ? "ecc" : "unknown")),
		pkey_get_bits(x),
		pkey_is_private(x));
}

X509CRT_PCTX FILE_getcrt(const char* fname) {
	unsigned char* buf = NULL;
	size_t len;
	X509CRT_PCTX r = NULL;

	printf("loading certificate from file (%s)....\n", fname);
	buf = FILE_getcontent(fname, &len);
	if (buf) {
		r = x509crt_load(buf, len);
		dumpcrt(r);
	}
	SAFE_FREE(buf);
	return r;
}

PKEY_PCTX FILE_getpvk(const char* fname) {
	unsigned char* buf = NULL;
	size_t len;
	PKEY_PCTX r = NULL;

	printf("loading private key from file (%s)....\n", fname);
	buf = FILE_getcontent(fname, &len);
	if (buf) {
		r = pkey_load_private(buf, len, NULL);
		dumpkey(r);
	}
	SAFE_FREE(buf);
	return r;
}

double benchmark_current_time(void) {
  struct timeval tv;
  gettimeofday(&tv, 0);

  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

void onalarm(int sig) {
	signal(SIGALRM, SIG_IGN);
	_bm.loop = 0;
}

void benchmark(int reset) {
	if (reset) {
		_bm.round = 0;
		_bm.loop = 1;
		signal(SIGALRM, onalarm);
		alarm(3);
		_bm.s = benchmark_current_time();
	}
	else {
		_bm.e = benchmark_current_time() - _bm.s;
	}
}

void hexdump(const unsigned char* s, int len) {
	int n;
	printf("(%d)\n", len);
	for (n = 0; n < len; n ++) {
		printf("%02x", s[n]);
		if (!((n + 1) % 8)) {
			printf("\n");
			continue;
		}
		if (!((n + 1) % 2)) {
			printf(" ");
			continue;
		}
	}
	printf("\n");
}

void hexdump2(const unsigned char* s, int len) {
	int n;
	printf("(%d)\n", len);
	for (n = 0; n < len; n ++) {
		printf("%02x", s[n]);
		if (!((n + 1) % 32)) {
			printf("\n");
			continue;
		}
		if (!((n + 1) % 2)) {
			printf(" ");
			continue;
		}
	}
	printf("\n");
}
