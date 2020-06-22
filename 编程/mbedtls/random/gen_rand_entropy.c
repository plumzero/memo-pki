#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/config.h"
#include "mbedtls/entropy.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define USAGE \
    "\n ./* <output filename>\n" \
    "\n <output filename>: random to write\n" \
    "\n"

/**
 使用基于多种熵源的伪随机数生成器生成伪随机数
 熵源来源：
    基于sha-256或sha-512的哈希算法
    havege
    平台有支持生成随机数的设备，如linux的/dev/urandom和Windows的Windows CryptoAPI
    半便携式定时器
    专用硬件熵源收集器
    基于不可变的文件集的熵源
 默认使用sha-512 + 半便携式定时器
 */
 
 int main(int argc, char * argv[])
 {
    int i, j, k, ret = 0;
    FILE *f;
    mbedtls_entropy_context entropy;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];  //每次只能收集 MBEDTLS_ENTROPY_BLOCK_SIZE 长度的熵

    if(argc < 2)
    {
        mbedtls_printf(USAGE);
        return -1;
    }

    if((f = fopen( argv[1], "wb+" )) == NULL)
    {
        mbedtls_printf( "failed to open '%s' for writing.\n", argv[1] );
        return -1;
    }
    //初始化熵源收集器
    mbedtls_entropy_init(&entropy);
    //多次调用熵源收集函数，获取足够的熵
    for(i = 0, k = 100; i < k; i++)
    {
        if ((ret = mbedtls_entropy_func(&entropy, buf, sizeof(buf))) != 0)
            goto cleanup;

        fwrite(buf, 1, sizeof( buf ), f);
        //观察，每次执行打印的结果均不一样
        for(j = 0; j < MBEDTLS_ENTROPY_BLOCK_SIZE; j++)
        {
            mbedtls_fprintf(stdout, "0x%02X ", buf[j]);
            if ((j & 0x0F ^ 0x0F) == 0)     //注意，比较运算符比位运算符的优先级要高！
                mbedtls_fprintf(stdout, "\n");
        }
        
        fflush(stdout);
    }
cleanup:
    fclose(f);
    mbedtls_entropy_free(&entropy);

    return ret;
}