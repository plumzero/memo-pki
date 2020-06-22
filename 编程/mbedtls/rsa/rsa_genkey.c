#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define KEY_SIZE 2048
#define EXPONENT 65537      //公钥指数，为了安全一般不应低于65536，考虑到计算时间，常设置为65537

//测试开关
#define DEBUG_RSA_KEYPAIR

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0)
    
#define USAGE   \
    "\n  ./* <pbk filename> <pvk filename>\n" \
    "\n    <pbk filename> <pvk filename>: write the core or crt parameters of keypair\n" \
    "\n"

void mbedtls_print_mpi(char * desc, mbedtls_mpi * X)
{
    int i, j, k, index = X->n - 1, tlen = sizeof(mbedtls_mpi_uint);

    mbedtls_printf("%s\n", desc);
    
    for(i = X->n - 1; i >= 0; i--, index--)
        if (X->p[i] != 0)
            break;
    for (i = index, k = 0; i >= 0; i--, k++)
    {
        for (j = tlen - 1; j >= 0; j--)
            mbedtls_printf("%02X", (X->p[i] >> (j << 3)) & 0xFF);
        if (k % 2)
            mbedtls_printf("\n");
    }
    if (k % 2)
        mbedtls_printf("\n");
}
    
int main(int argc, char *argv[])
{
    int ret = 0;
    
    FILE *fpbk  = NULL;
    FILE *fpvk = NULL;

    const char *indiv_data = "created by C";
    
    mbedtls_rsa_context rsa_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    
    if (argc != 3)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    if ((fpbk = fopen(argv[1], "wb+")) == NULL)
    {
        mbedtls_fprintf(stderr, "fopen(%s,wb+) failed\n", argv[1]);
        goto cleanup;
    }
    if ((fpvk = fopen(argv[2], "wb+")) == NULL)
    {
        mbedtls_fprintf(stderr, "fopen(%s,wb+) failed\n", argv[2]);
        goto cleanup;
    }
    
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);
    
    //将熵源设置为伪随机数种子 
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (const unsigned char *)indiv_data, strlen(indiv_data))) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_RSA_KEYPAIR
    mbedtls_print_mpi("Before N: ", &rsa_ctx.N);
    mbedtls_print_mpi("Before D: ", &rsa_ctx.D);
    mbedtls_print_mpi("Before E: ", &rsa_ctx.E);
#endif
    //生成rsa密钥对
    if ((ret = mbedtls_rsa_gen_key(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, 
                                    EXPONENT)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_RSA_KEYPAIR
    mbedtls_print_mpi("After N: ", &rsa_ctx.N);
    mbedtls_print_mpi("After D: ", &rsa_ctx.D);
    mbedtls_print_mpi("After E: ", &rsa_ctx.E);
#endif
    //将核心参数和剩余参数导出
    if ((ret = mbedtls_rsa_export(&rsa_ctx, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(&rsa_ctx, &DP, &DQ, &QP)) != 0)
        mbedtls_err(ret);
    //写入磁盘
    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpbk)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpbk)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, fpvk)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = ", &E, 16, fpvk)) != 0 ||
        (ret = mbedtls_mpi_write_file("D = ", &D, 16, fpvk)) != 0 ||
        (ret = mbedtls_mpi_write_file("P = ", &P, 16, fpvk)) != 0 ||
        (ret = mbedtls_mpi_write_file("Q = ", &Q, 16, fpvk)) != 0 ||
        (ret = mbedtls_mpi_write_file("DP = ", &DP, 16, fpvk)) != 0 ||
        (ret = mbedtls_mpi_write_file("DQ = ", &DQ, 16, fpvk)) != 0 ||
        (ret = mbedtls_mpi_write_file("QP = ", &QP, 16, fpvk)) != 0)
        mbedtls_err(ret);
    mbedtls_fprintf(stdout, "ret (%02x)\n", ret);
cleanup:
    if (fpbk) fclose(fpbk);
    if (fpvk) fclose(fpvk);

    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
    mbedtls_rsa_free(&rsa_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return ret;
}
