#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/md.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define USAGE   \
    "\n  ./* <hash> <file> [key]\n" \
    "\n    <hash>: Supported type: SHA1 SHA224 SHA256 SHA384 SHA512 MD5\n" \
    "\n    [key]: optional\n" \
    "\n"
/**
 说明 哈希过程中混合（共享）密钥生成消息认证码(hmac)，消息认证码也是一种哈希
 运行 ./程序名 哈希算法 文件全路径名 [密钥]
 注意 每种算法库混合密钥机制不同，所以同样的哈希算法+同样的密钥+同样的文件，得到的结果未必相同
 */
int main(int argc, char * argv[])
{   
    int i, n, siglen, ret = 0;
    size_t blen, keylen;
    FILE * fin;
    unsigned char buf[1024];
    unsigned char key[512];
    unsigned char digest[128];
    const mbedtls_md_info_t * md_info;
    mbedtls_md_context_t md_ctx;

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
    
    argv[3] ? strcpy(key, argv[3]) : strcpy(key, "HYDn2XDKdV0Om8M8EjuL95T4L4AHpulV");
    keylen = strlen(key);
    
    mbedtls_md_init(&md_ctx);
    
    if((md_info = mbedtls_md_info_from_string(argv[1])) == NULL)
        goto cleanup;
    
    siglen = mbedtls_md_get_size(md_info);
    
    if((ret = mbedtls_md_setup(&md_ctx, md_info, 1)) != 0)  /* 最后一个参数必须打开 */
        goto cleanup;
        
    if((ret = mbedtls_md_hmac_starts(&md_ctx, key, keylen)) != 0)
        goto cleanup;
    
    while((n = fread(buf, 1, sizeof(buf), fin)) > 0)
        if((ret = mbedtls_md_hmac_update(&md_ctx, buf, n)) != 0)
            goto cleanup;
    
    if (ferror(fin) != 0)
        ret = MBEDTLS_ERR_MD_FILE_IO_ERROR;
    else
    {
        if((ret = mbedtls_md_hmac_finish(&md_ctx, digest)) != 0)
            goto cleanup;
    }
    
    for(i = 0; i < siglen; i++)
        mbedtls_printf("%02x", digest[i]);

    mbedtls_printf( "\n" );

cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));
    fclose(fin);
    mbedtls_md_free(&md_ctx);
    return ret;
}