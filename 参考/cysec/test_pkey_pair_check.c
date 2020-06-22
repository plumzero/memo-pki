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

void usage(void)
{
	printf("--cert the cert file.\n");
	printf("--in CFCA private file.\n");
	printf("--out standard ec private file.\n");
	printf("--check check private with public key.\n");
	exit(1);
}

/**
	¹«Ë½Ô¿Æ¥Åä¼ì²â
 */
int main(int argc, char **argv)
{
	const char *cert_file = NULL, *in = NULL, *out = NULL;
	int check = 0;
	PKEY_PCTX pub = NULL, priv = NULL;
	X509CRT_PCTX cert = NULL;
	unsigned char *out_pem = NULL;
	size_t out_size = 0;
	int ret = 0;

	argc--;
	argv++;

	while(argc > 0){
		if(strcmp(*argv,"--cert") == 0){
		  if(--argc<1)
		    break;
		  cert_file = *(++argv);
		}else if(strcmp(*argv,"--in") == 0){
		  if(--argc<1)
		    break;
		  in = *(++argv);
		} else if(strcmp(*argv,"--out") == 0) {
		  if(--argc<1)
		    break;
		  out = *(++argv);
		} else if(strcmp(*argv,"--check") == 0) {
			check=1;
		} else if (strcmp(*argv, "--help") == 0 ) {
			usage();
		}
		else
		  break;
		argc--;
		argv++;
	}

	if (!in || !out) {
		printf(" need private key (in && out).\n");
		exit(1);
	}

	if(check && !(cert_file)) {
		printf(" need certificate file for checking.\n");
		exit(1);
	}

	priv = FILE_getpvk(in);
	if(!priv) {
		printf(" failed to load private from %s\n", in);
		exit(1);
	}

	ret = cysec_pkey_export_privatekey(priv, &out_pem, &out_size, PEM);
	if(ret){
		printf("export private key failed, ret=%08x\n", ret);
		goto err;
	}

	ret = FILE_putcontent(out_pem, out_size, out);
	if(ret){
		printf("write to %s failed.\n", out);
		goto err;
	}

	if(check){
		cert=FILE_getcrt(cert_file);
		if(!cert){
			printf("failed to load certificate from %s \n", cert_file);
			goto err;
		}
		
		pub = cysec_x509crt_get_publickey(cert);
		if(!pub){
			printf("failed to load public key \n");
			goto err;
		}

		ret = cysec_pkey_check_pair(pub, priv);
		if(ret == 0) {
			printf("match.\n");
		}else{
			printf("mismatch.\n");
		}
	}

err:
	if(priv)
		cysec_pkey_free(priv);
	if(pub)
		cysec_pkey_free(pub);
	if(cert)
		cysec_x509crt_free(cert);
	if(out_pem)
		free(out_pem);

	return ret;
}