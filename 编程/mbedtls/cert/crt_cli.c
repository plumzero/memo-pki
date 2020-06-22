#include <stdio.h>
#include <stdint.h>

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

#define DER_FORMAT          1
#define PEM_FORMAT          2

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

#define USAGE   \
    "\n  ./* <cert path>\n" \
    "\n"

/*
    功能：
        对一个X509证书进行解析
    命令格式：
    
 */
int main(int argc, char *argv[])
{
    int format, ret = 0;
    unsigned char *crtbuf = NULL;
    size_t crtlen;
    
    mbedtls_x509_crt crt_ctx;
    
    if (argc < 3)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    //命令解析
    format = strcmp(argv[2], "pem") == 0 ? PEM_FORMAT : (strcmp(argv[2], "der") == 0 ? DER_FORMAT : -1);
    if (format != PEM_FORMAT && format != DER_FORMAT)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    //读入缓冲
    if ((ret =mbedtls_pk_load_file(argv[1], &crtbuf, &crtlen)) != 0)
        mbedtls_err(ret);
    
    
    
    
    
cleanup:
    mbedtls_fprintf(stderr, "ret (%8X)\n", ret);
    if (crtbuf) { free(crtbuf); crtbuf = NULL; }
    
    
    
    return ret;
}