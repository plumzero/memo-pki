#ifndef _SHGM_SDK_UTIL_H_
#define _SHGM_SDK_UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define x_malloc(x) calloc(1, x)
#define x_free(x) free(x)

#if __DEBUG__
#define s_log(fmt, arg...) \
	do { \
		printf("%s:%d " fmt "\n", __FILE__, __LINE__, ##arg); \
	} while(0)

#define s_err(fmt, arg...) \
	do { \
		printf("[ERROR] %s:%d " fmt "\n", __FILE__, __LINE__, ##arg); \
	} while(0)
#else
#define s_log(fmt, arg...) do {} while (0)
#define s_err(fmt, arg...) do {} while (0)
#endif


#define s_assert(v, fmt, arg...) \
	do { \
		if (!(v)) { \
			printf("[ASSERT] %s:%d " fmt "\n", __FILE__, __LINE__, ##arg); \
		} \
	} while(0)

#define SAFE_FREE(x) \
	do { \
		if (x) x_free(x); \
		x = NULL; \
	} while(0)

void hexdump(const unsigned char* s, int len);
char* as_string(const char* s, int len);
char* as_hexstring(const unsigned char* s, int len);

#endif
