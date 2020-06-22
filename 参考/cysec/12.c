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

const char * message = 
"-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwTsXFnRrzkEIUxxlF/Mm\n\
PwXyAC6Xvn8nC9+x+jZp8XX5ociZvLBC93PiAYYsyQd8TPTxVY1yWfXYA3esz3Es\n\
DBIyXTrxyKgNGo2ot4XRfR7pvma1bDMA5euKkOiEA6UhoEkIAhgRb+JsdWnkgyUy\n\
gboOhZPpQ5DNmKPcL8YlsCg1qUSRwkUMiumLaobEIxogjkJ4wW/5XHQbVuYHzhng\n\
YydfuPlBSA0WBvgf9Bl55INLNjoo+eII7GXTNBKzrlyopDMcwKxB19umIQFciWKd\n\
EqY7PU/2eg0DSAFMbm36JAp8NGB7lhbc+zPK2Rh2xVNpuDb8yHL6PqAXSoPDYxAu\n\
aQIDAQAB\n\
-----END PUBLIC KEY-----";

int main()
{
	PKEY_PCTX pctx = FILE_getpvk("./kpool/rsa.pvk.pem");
	
	int ret;
	unsigned char *pem_pub = NULL, *pem_prv = NULL;
	size_t publen = 0, privlen = 0;
	
	ret = cysec_pkey_export_privatekey(pctx, &pem_prv, &privlen, PEM);
	printf ("%s\n", pem_prv);
	ret = cysec_pkey_export_publickey(pctx, &pem_pub, &publen, PEM);
	printf ("%s\n", pem_pub);
	
	PKEY_PCTX pctx_pub = NULL;
	pctx_pub = cysec_pkey_load_public(pem_prv, privlen);
	s_assert((pctx_pub != NULL),"failure to load public key 111");
	pctx_pub = cysec_pkey_load_public(pem_pub, publen);
	s_assert((pctx_pub != NULL),"failure to load public key 222");
	pctx_pub = cysec_pkey_load_public(message, strlen(message));
	s_assert((pctx_pub != NULL),"failure to load public key");
	
	return 0;
}