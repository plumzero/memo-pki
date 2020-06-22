#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/md.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define USAGE   \
    "\n  ./* <hash> <file path>\n" \
    "\n    <hash>: Supported type: SHA1 SHA224 SHA256 SHA384 SHA512 MD5\n" \
    "\n"
/**
 说明 对文件进行哈希，一次只能哈希一个
 运行 ./程序名 哈希算法 文件全路径名
 */
int main(int argc, char * argv[])
{   
    int i, n, siglen, ret = 0;
    FILE * fin;
    size_t blen, keylen;
    unsigned char buf[1024];
    unsigned char key[512];
    unsigned char digest[128];
    const mbedtls_md_info_t * md_info;
    mbedtls_md_context_t md_ctx;
    
    if( argc != 3 )
    {
        mbedtls_printf( USAGE );
        return -1;
    }
    
    if(strcmp("SHA1", argv[1]) && strcmp("SHA224", argv[1]) && strcmp("SHA256", argv[1]) 
        && strcmp("SHA384", argv[1]) && strcmp("SHA512", argv[1]) && strcmp("MD5", argv[1]))
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    if((fin = fopen(argv[2], "rb")) == NULL)
    {
        mbedtls_fprintf(stderr, "fopen(%s,rb) failed\n", argv[2]);
        return MBEDTLS_ERR_MD_FILE_IO_ERROR;
    }

    mbedtls_md_init(&md_ctx);
    
    if((md_info = mbedtls_md_info_from_string(argv[1])) == NULL)
        goto cleanup;
    
    siglen = mbedtls_md_get_size(md_info);
    
    if((ret = mbedtls_md_setup(&md_ctx, md_info, 0)) != 0)
        goto cleanup;
    
    mbedtls_md_starts(&md_ctx);
    
    while((n = fread(buf, 1, sizeof(buf), fin)) > 0)
        mbedtls_md_update(&md_ctx, buf, n);
    
    if(ferror(fin) != 0)
        ret = MBEDTLS_ERR_MD_FILE_IO_ERROR;
    else
        ret = mbedtls_md_finish(&md_ctx, digest);
    
    for(i = 0; i < siglen; i++)
        mbedtls_printf("%02x", digest[i]);

    mbedtls_printf( "\n" );

cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));
    mbedtls_md_free(&md_ctx);
    fclose(fin);
    return ret;
}