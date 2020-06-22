#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

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

char* as_string(const char* s, int len) {
	char* r = x_malloc(len + 1);
	memcpy(r, s, len);
	return r;
}

char* as_hexstring(const unsigned char* s, int len) {
	char* r = x_malloc(len * 2 + 1);
	int n;
	for (n = 0; n < len; n ++) {
		sprintf(r + (n * 2), "%02x", s[n]);
	}
	return r;
}

