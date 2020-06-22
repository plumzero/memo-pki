#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/md.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

/**
 说明 字符串的哈希  
 运行 ./程序名 哈希算法 [字符串]
 其他 借助 http://tool.oschina.net/encrypt?type=2 工具测试完成
 */
/**
 部分哈希算法类型及结果位数
 MD5        16
 SHA1       20
 SHA256     32
 SHA512     64
 */
 
#define USAGE   \
    "\n  ./* <hash> [string]\n" \
    "\n    <hash>: Supported type: SHA1 SHA224 SHA256 SHA384 SHA512 MD5\n" \
    "\n    [string]: optional\n" \
    "\n"

int main(int argc, char * argv[])
{   
    int i, siglen, ret = 0; /* 后面会涉及与i的比较，为了避免强制这里将siglen定义为int类型 */
    size_t ilen;
    unsigned char input[1024];
    unsigned char digest[128];
    const mbedtls_md_info_t * md_info;
    mbedtls_md_context_t md_ctx;

    if(strcmp("SHA1", argv[1]) && strcmp("SHA224", argv[1]) && strcmp("SHA256", argv[1]) 
        && strcmp("SHA384", argv[1]) && strcmp("SHA512", argv[1]) && strcmp("MD5", argv[1]))
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    argv[2] ? strcpy(input, argv[2]) : strcpy(input, "Hello World!");
    
    ilen = strlen(input);
    
    mbedtls_md_init(&md_ctx);
    
    if((md_info = mbedtls_md_info_from_string(argv[1])) == NULL)
        goto cleanup;
    
    siglen = mbedtls_md_get_size(md_info);
    
    if ((ret = mbedtls_md_setup(&md_ctx, md_info, 0)) != 0)
        goto cleanup;
    
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, input, ilen);
    mbedtls_md_finish(&md_ctx, digest);
    
    for(i = 0; i < siglen; i++)
        mbedtls_printf("%02x", digest[i]);

    mbedtls_printf( "\n" );

cleanup:
    mbedtls_md_free(&md_ctx);
    return ret;
}
