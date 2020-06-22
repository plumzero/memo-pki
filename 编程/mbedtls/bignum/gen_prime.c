#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define GENERATOR "64"

#define USAGE   \
    "\n  ./* <random nbits> <output filename>\n" \
    "\n    <random nbits>: do not set too much(<1024) while running in low performance cpu\n" \
    "\n"

void printMPI(char * desc, mbedtls_mpi * X)
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
    int nbits, ret = 0;
    mbedtls_mpi G, P, Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "personal parameters";
    FILE *fout;

    if (argc < 3)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    if ((ret = sscanf(argv[1], "%d", &nbits)) == 0)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    if ((fout = fopen(argv[2], "wb+")) == NULL)
        goto cleanup;
    
    //初始化大数
    mbedtls_mpi_init(&G); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    //基于aes分组加密的伪随机数生成器初始化
    mbedtls_ctr_drbg_init(&ctr_drbg);
    //熵源收集器初始化
    mbedtls_entropy_init(&entropy);

    //读取大数
    if ((ret = mbedtls_mpi_read_string(&G, 10, GENERATOR)) != 0)
        goto cleanup;
    
    mbedtls_printf("Generating large primes may take minutes!");
    
    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);
    //设置发生器参数 将熵源收集器作为生成器ctr_drbg的种子
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)pers, strlen(pers))) != 0)
        goto cleanup;

    mbedtls_printf(" ok\n  . Generating the modulus, please wait...");
    fflush(stdout);
    //生成二进制长度为nbits的大素数 P
    if ((ret = mbedtls_mpi_gen_prime(&P, nbits, 1,
                               mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        goto cleanup;

    mbedtls_printf(" ok\n  . Verifying that Q = (P-1)/2 is prime...");
    fflush(stdout);
    //计算 P - 1
    if (( ret = mbedtls_mpi_sub_int(&Q, &P, 1)) != 0)
        goto cleanup;
    //计算 (P - 1) / 2
    if ((ret = mbedtls_mpi_div_int(&Q, NULL, &Q, 2)) != 0)
        goto cleanup;
    //(P - 1) / 2 是否为素数（米勒-拉宾素性测试）
    if ((ret = mbedtls_mpi_is_prime(&Q, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        goto cleanup;
    //写入文件
    mbedtls_printf(" ok\n  . Exporting the value in %s...", argv[2]);
    if ((ret = mbedtls_mpi_write_file("P = ", &P, 16, fout) != 0) ||
        (ret = mbedtls_mpi_write_file("G = ", &G, 16, fout) != 0))
        goto cleanup;
    mbedtls_printf(" ok\n\n");
    //每次执行的打印都不一样
    printMPI("P: ", &P);
    printMPI("Q: ", &Q);
    printMPI("G: ", &G);
cleanup:
    mbedtls_printf("ret (0x%08X)\n", ret);
    mbedtls_mpi_free(&G); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    fclose(fout);
    return ret;
}
