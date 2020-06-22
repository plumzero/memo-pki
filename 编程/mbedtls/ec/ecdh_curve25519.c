#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

#define DEBUG_ECDH

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

void mbedtls_ecdh_print_keypair(mbedtls_ecdh_context *ed)
{
    //打印公钥
    mbedtls_mpi_vprint(&ed->Q.X, "public.Q.X\n");
    mbedtls_mpi_vprint(&ed->Q.Y, "public.Q.Y\n");
    //打印私钥
    mbedtls_mpi_vprint(&ed->d, "private.d\n");
}

int main(int argc, char *argv[])
{
    int ret = 0;
    const char *indiv_data = "Created by C";
    unsigned char cli_to_srv[32], srv_to_cli[32];
    
    mbedtls_ecdh_context ctx_cli, ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_ecdh_init(&ctx_cli);
    mbedtls_ecdh_init(&ctx_srv);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    //随机数种子
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, indiv_data, strlen(indiv_data))) != 0)
        mbedtls_err(ret);
    //客户端：指定椭圆曲线
    if ((ret = mbedtls_ecp_group_load(&ctx_cli.grp, MBEDTLS_ECP_DP_CURVE25519)) != 0)
        mbedtls_err(ret);
    //客户端：在椭圆曲线上生成一个ECDH密钥对
    if ((ret = (mbedtls_ecdh_gen_public(&ctx_cli.grp, &ctx_cli.d, &ctx_cli.Q, mbedtls_ctr_drbg_random, &ctr_drbg))) != 0)
        mbedtls_err(ret);
    //客户端：写入发送给服务端的缓存
    if ((ret = mbedtls_mpi_write_binary(&ctx_cli.Q.X, cli_to_srv, 32)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECDH
    mbedtls_printf("%d client keypair:\n", __LINE__);
    mbedtls_ecdh_print_keypair(&ctx_cli);
#endif
    /**************************************************************************************************************************************************************/
    //服务端：指定椭圆曲线
    if ((ret = mbedtls_ecp_group_load(&ctx_srv.grp, MBEDTLS_ECP_DP_CURVE25519)) != 0)
        mbedtls_err(ret);
    //服务端：在椭圆曲线上生成一个ECDH密钥对
    if ((ret = mbedtls_ecdh_gen_public(&ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
    //服务端：写入发送给客户端的缓存
    if ((ret = mbedtls_mpi_write_binary(&ctx_srv.Q.X, srv_to_cli, 32)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECDH
    mbedtls_printf("%d server keypair:\n", __LINE__);
    mbedtls_ecdh_print_keypair(&ctx_srv);
#endif
    /**************************************************************************************************************************************************************/
    if ((ret = mbedtls_mpi_lset(&ctx_srv.Qp.Z, 1)) != 0)
        mbedtls_err(ret);
    //服务端：读取客户端发来的公共值
    if ((ret = mbedtls_mpi_read_binary(&ctx_srv.Qp.X, cli_to_srv, 32)) != 0)
        mbedtls_err(ret);
    //服务端：计算共享密钥
    if((ret = mbedtls_ecdh_compute_shared(&ctx_srv.grp, &ctx_srv.z, &ctx_srv.Qp, &ctx_srv.d, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECDH
    mbedtls_mpi_vprint(&ctx_srv.z, "%d shared:\n", __LINE__);
#endif
    /**************************************************************************************************************************************************************/
    if ((ret = mbedtls_mpi_lset(&ctx_cli.Qp.Z, 1)) != 0)
        mbedtls_err(ret);
    //客户端：读取服务端发来的公共值
    if ((ret = mbedtls_mpi_read_binary(&ctx_cli.Qp.X, srv_to_cli, 32)) != 0)
        mbedtls_err(ret);
    //客户端：计算共享密钥
    if ((ret = mbedtls_ecdh_compute_shared(&ctx_cli.grp, &ctx_cli.z, &ctx_cli.Qp, &ctx_cli.d, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECDH
    mbedtls_mpi_vprint(&ctx_cli.z, "%d shared:\n", __LINE__);
#endif
    /**************************************************************************************************************************************************************/
    //比较是否相等
    if ((ret = mbedtls_mpi_cmp_mpi(&ctx_cli.z, &ctx_srv.z)) != 0)
        mbedtls_err(ret);
cleanup:
    mbedtls_printf("ret (%08X)\n", ret);
    mbedtls_ecdh_free(&ctx_srv);
    mbedtls_ecdh_free(&ctx_cli);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}