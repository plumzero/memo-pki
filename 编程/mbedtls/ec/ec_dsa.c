#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

#define DEBUG_ECDSA
// #define ALTERNATIVE_PRINT_PUBKEY

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

void mbedtls_mpi_vprint(mbedtls_mpi * X, const char * format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    int i, j, k, index = X->n - 1, tlen = sizeof(mbedtls_mpi_uint);

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

void mbedtls_ecdsa_print_keypair(mbedtls_ecdsa_context *key)
{
    int i, ret = 0;
    unsigned char buf[300];
    size_t len, plen;
    
    if ((ret = mbedtls_ecp_point_write_binary(&key->grp, &key->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf)) != 0)
        mbedtls_err(ret);
    
    //密钥长度
    mbedtls_printf("key size: %d bits\n", (int)key->grp.pbits);
    //打印公钥
    mbedtls_mpi_vprint(&key->Q.X, "public.Q.X\n");
    mbedtls_mpi_vprint(&key->Q.Y, "public.Q.Y\n");
#ifdef ALTERNATIVE_PRINT_PUBKEY
    //也可以使用下列打印公钥
    plen = mbedtls_mpi_size(&key->grp.P);
    if (plen * 2 + 1 != len)
    {
        ret = -1;
        goto cleanup;
    }
    for (i = 1; i < plen + 1; i++)
        mbedtls_printf("%c%c", "0123456789ABCDEF"[buf[i] / 16], "0123456789ABCDEF"[buf[i] % 16]);
    mbedtls_printf("\n");
    for (; i < len; i++)
        mbedtls_printf("%c%c", "0123456789ABCDEF"[buf[i] / 16], "0123456789ABCDEF"[buf[i] % 16]);
    mbedtls_printf("\n");
#endif
    //打印私钥
    mbedtls_mpi_vprint(&key->d, "private.d\n");
    
cleanup:
    if (ret)
        mbedtls_fprintf(stderr, "ret (%08X)\n", ret);
}
/**
    椭圆曲线数字签名算法（ECDSA）是使用椭圆曲线密码（ECC）对数字签名算法（DSA）的模拟
 */
int main(int argc, char *argv[])
{
    int i, ret = 0;
    
    size_t sig_len;
    
    const char *indiv_data = "Created by C";
    unsigned char message[100];
    unsigned char hash[32];     //sha256的哈希值长度为32字节
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    
    memset(message, 0x41, sizeof message);
    
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    //随机数种子
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, indiv_data, strlen(indiv_data))) != 0)
        mbedtls_err(ret);
    //生成签名密钥对
    if ((ret = mbedtls_ecdsa_genkey(&ctx_sign, MBEDTLS_ECP_DP_SECP521R1, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECDSA
    //打印密钥对
    mbedtls_ecdsa_print_keypair(&ctx_sign);
#endif
    //进行简单的哈希
    if ((ret = mbedtls_sha256_ret(message, sizeof message, hash, 0)) != 0)
        mbedtls_err(ret);
    //签名
    if ((ret = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256, hash, sizeof hash, sig, &sig_len,
                                                mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
    mbedtls_printf("  signature ok!\n");
#ifdef DEBUG_ECDSA
    mbedtls_printf("hash:\n");
    for (i = 0; i < 32; i++)
        mbedtls_printf("%c%c", "0123456789ABCDEF"[hash[i] / 16], "0123456789ABCDEF"[hash[i] % 16]);
    mbedtls_printf("\nsignature:\n");
    for (i = 0; i < (int)sig_len; i++)
        mbedtls_printf("%c%c", "0123456789ABCDEF"[sig[i] / 16], "0123456789ABCDEF"[sig[i] % 16]);
    mbedtls_printf("\n");
#endif
    //拷贝椭圆曲线算法配置
    if ((ret = mbedtls_ecp_group_copy(&ctx_verify.grp, &ctx_sign.grp)) != 0)
        mbedtls_err(ret);
    //公钥拷贝
    if ((ret = mbedtls_ecp_copy(&ctx_verify.Q, &ctx_sign.Q)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECDSA
    //打印密钥对
    mbedtls_ecdsa_print_keypair(&ctx_verify);
#endif
    //验签
    if ((ret = mbedtls_ecdsa_read_signature(&ctx_verify, hash, sizeof hash, sig, sig_len)) != 0)
        mbedtls_err(ret);
    mbedtls_printf("  verify ok!\n");

cleanup:
    mbedtls_printf("ret (%08X)\n", ret);
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return ret;
}