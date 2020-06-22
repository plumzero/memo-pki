#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

int main()
{
	PKEY_PCTX pctx = NULL;
	pctx = cysec_pkey_gen_rsa(1024);
	if (pctx)
		printf("success\n");
	else
		printf("failed\n");
	
	return 0;
}