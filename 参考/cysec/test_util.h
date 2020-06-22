#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

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

struct benchmark_st {
	int loop;
	int round;
	double s;
	double e;
};

struct benchmark_st _bm;

unsigned char* FILE_getcontent(const char* fname, size_t* len);
int FILE_putcontent(const unsigned char *in, size_t ilen, const char *fname);
void dumpcrt(X509CRT_PCTX x);
void fillbuf(unsigned char* buf, size_t blen);
void dumpcrt(X509CRT_PCTX x);
void dumpkey(PKEY_PCTX x);
X509CRT_PCTX FILE_getcrt(const char* fname);
PKEY_PCTX FILE_getpvk(const char* fname);
double benchmark_current_time(void);
void onalarm(int sig);
void benchmark(int reset);
void hexdump(const unsigned char* s, int len);
void hexdump2(const unsigned char* s, int len);
