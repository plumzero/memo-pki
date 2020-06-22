#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

/**
 使用基于aes加密算法的伪随机数生成器生成伪随机数
 */
/**
 熵源回调参数
 伪随机数种子就是通过该参数和熵源回调生成的
 也就是说，如果熵源回调及其参数相同，则生成的伪随机数种子也相同(不设置个性化参)
*/
static const unsigned char entropy_source[96] =
    { 0xc1, 0x80, 0x81, 0xa6, 0x5d, 0x44, 0x02, 0x16,
      0x19, 0xb3, 0xf1, 0x80, 0xb1, 0xc9, 0x20, 0x02,
      0x6a, 0x54, 0x6f, 0x0c, 0x70, 0x81, 0x49, 0x8b,
      0x6e, 0xa6, 0x62, 0x52, 0x6d, 0x51, 0xb1, 0xcb,
      0x58, 0x3b, 0xfa, 0xd5, 0x37, 0x5f, 0xfb, 0xc9,
      0xff, 0x46, 0xd2, 0x19, 0xc7, 0x22, 0x3e, 0x95,
      0x45, 0x9d, 0x82, 0xe1, 0xe7, 0x22, 0x9f, 0x63,
      0x31, 0x69, 0xd2, 0x6b, 0x57, 0x47, 0x4f, 0xa3,
      0x37, 0xc9, 0x98, 0x1c, 0x0b, 0xfb, 0x91, 0x31,
      0x4d, 0x55, 0xb9, 0xe9, 0x1c, 0x5a, 0x5e, 0xe4,
      0x93, 0x92, 0xcf, 0xc5, 0x23, 0x12, 0xd5, 0x56,
      0x2c, 0x4a, 0x6e, 0xff, 0xdc, 0x10, 0xd0, 0x68 };
//个性化参数
static const unsigned char nonce_pers[16] =
    { 0xd2, 0x54, 0xfc, 0xff, 0x02, 0x1e, 0x69, 0xd2,
      0x29, 0xc9, 0xcf, 0xad, 0x85, 0xfa, 0x48, 0x6c };
static size_t test_offset;
//（用于测试的）熵源回调
static int ctr_drbg_self_test_entropy(void *data, unsigned char *buf,
                                       size_t len)
{
    const unsigned char *p = data;
    memcpy(buf, p + test_offset, len);
    test_offset += len;
    return( 0 );
}

static void print(unsigned char *buf, int blen)
{
    int i;
    for (i = 0; i < blen; i++)
        (i + 1) % 16 != 0 ? mbedtls_printf("0x%02X ", buf[i]) : mbedtls_printf("0x%02X\n", buf[i]);
}

#define RANDOM_SIZE     1024

int main(int argc, char * argv[])
{
    int i, ret = 0;
    
    mbedtls_ctr_drbg_context ctx;
    unsigned char buf[RANDOM_SIZE];
    
    test_offset = 0;
    //伪随机数发生器初始化
    mbedtls_ctr_drbg_init(&ctx);

#ifdef SERVER_USE
    //熵源足够时使用
    mbedtls_printf("Prediction Resistance is ON.\n");
    //基本设置 回调函数及传参 个性化参数
    if ((ret = mbedtls_ctr_drbg_seed(&ctx, ctr_drbg_self_test_entropy, (void *)entropy_source, 
                                        nonce_pers, sizeof(nonce_pers))) != 0)
        goto exit;
    //打开PR
    mbedtls_ctr_drbg_set_prediction_resistance(&ctx, MBEDTLS_CTR_DRBG_PR_ON);
    //生成伪随机数，可多次调用。每调用一次都会进行一次熵源回调
    if ((ret = mbedtls_ctr_drbg_random(&ctx, buf, RANDOM_SIZE)) != 0)
        goto exit;
    if ((ret = mbedtls_ctr_drbg_random(&ctx, buf, RANDOM_SIZE)) != 0)
        goto exit;
#else
    mbedtls_printf("Prediction Resistance is OFF.\n");
    if ((ret = mbedtls_ctr_drbg_seed(&ctx, ctr_drbg_self_test_entropy, (void *)entropy_source, 
                                        NULL, 0)) != 0)
        goto exit;
    
    if ((ret = mbedtls_ctr_drbg_random(&ctx, buf, RANDOM_SIZE)) != 0)
        goto exit;
    print(buf, RANDOM_SIZE);
    //重置熵源回调，重新设置个性化参数，这里是清空
    if ((ret = mbedtls_ctr_drbg_reseed(&ctx, NULL, 0)) != 0)
        goto exit;
    if ((ret = mbedtls_ctr_drbg_random(&ctx, buf, RANDOM_SIZE)) != 0)
        goto exit;

#endif
    //打印伪随机数
    print(buf, RANDOM_SIZE);
    
exit:
    mbedtls_printf("ret (%d)\n", ret);
    mbedtls_ctr_drbg_free(&ctx);
    return ret;
}