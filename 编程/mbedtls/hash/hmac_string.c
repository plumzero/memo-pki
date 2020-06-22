#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/md.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define USAGE   \
    "\n  ./* <hash> [key] [string]\n" \
    "\n    <hash>: Supported type: SHA1 SHA224 SHA256 SHA384 SHA512 MD5\n" \
    "\n    [key]: optional\n" \
    "\n    [string]: optional\n" \
    "\n"
/**
 说明 哈希过程中混合（共享）密钥生成消息认证码(hmac)，消息认证码也是一种哈希
 运行 ./程序名 哈希算法 [密钥] [字符串]
 注意 每种算法库混合密钥机制不同，所以同样的哈希算法+同样的密钥+同样的字符串，得到的结果未必相同
 */
/**
 可以将本程序整合为一个，如下：
    int mbedtls_md_hmac( const mbedtls_md_info_t *md_info,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t ilen,
                     unsigned char *output );
 事实上，上述函数位于 md5.c 中
 */
int main(int argc, char * argv[])
{   
    int i, siglen, ret = 0;
    size_t ilen, keylen;
    unsigned char input[1024];
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
    
    argv[2] ? strcpy(key, argv[2]) : strcpy(key, "HYDn2XDKdV0Om8M8EjuL95T4L4AHpulV");
    keylen = strlen(key);
    
    argv[3] ? strcpy(input, argv[3]) : strcpy(input, "Hello World!");
    ilen = strlen(input);
    
    mbedtls_md_init(&md_ctx);
    
    if((md_info = mbedtls_md_info_from_string(argv[1])) == NULL)
        goto cleanup;
    
    siglen = mbedtls_md_get_size(md_info);
    
    if((ret = mbedtls_md_setup(&md_ctx, md_info, 1)) != 0)  /* 最后一个参数必须打开 */
        goto cleanup;
        
    if((ret = mbedtls_md_hmac_starts(&md_ctx, key, keylen)) != 0)
        goto cleanup;
    if((ret = mbedtls_md_hmac_update(&md_ctx, input, ilen)) != 0)
        goto cleanup;
    if((ret = mbedtls_md_hmac_finish(&md_ctx, digest)) != 0)
        goto cleanup;
    
    for(i = 0; i < siglen; i++)
        mbedtls_printf("%02x", digest[i]);

    mbedtls_printf( "\n" );

cleanup:
    mbedtls_md_free(&md_ctx);
    return ret;
}