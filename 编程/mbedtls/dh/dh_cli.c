#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

#define DEBUG_CLIENT

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

#define USAGE   \
    "\n  ./* <host> <port>\n" \
    "\n"

#define BUF_SIZE    2048

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

//服务端公钥
static const char rsaN[] = {
    "98A9CA5F58174A1C5D25B56EFCA257FE5FC1A35DA15CD58816C9D31C4FF715F9"  
    "D89CE330A364A89D41D97CA59016C142BE205D2A8048ABD1C05BF3E6B0A61973"
    "68770C885E0A879B500EA801BFE24CBF8AC3535DA305F7185786DFE5CAD13B4D"
    "4A36B560A1285C0E1F7A34F9D076025FC77155C1C6D2DF034DBE53DEC9CEDD16"
    "73F1F81EDBD0602937272343E0EEBB43A0451981F8C6FC01489C168352612388"
    "30EE731504600A3A8E8155BB0D3FEE57496CD4A195FBF7873EB0D5B8B78CE1CA"
    "33AAE930A6B6814127D9B32513525879D5B4F8FB54F27DB206611D7FBBE05D2B"
    "4691331C1D23FB211D19354BD574510108E5FFFFFFD711B2D729E393A892F973"
};
static const char rsaE[] = {
    "010001"
};

/**
    功能：
        Diffile-Hellman协议下的密钥参数交换 客户端
    注意事项：
        1.本程序未做详细传参检验，传入参数需严格执行
        2.buf缓冲区内容格式
            [两字节用于存储总长度][SKE][两字节用于存储SKE签名长度][SKE签名]                
 */
int main(int argc, char *argv[])
{
    int i, nr, nleft, len, done, ret = 0;
    size_t n;
    unsigned char buf[BUF_SIZE];
    unsigned char hbuf[128];
    unsigned char *p, *end;
    const char *indiv_data = "Created by C";
    
    if (argc < 3)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    const mbedtls_md_info_t *md_info = NULL;
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa_ctx;
    mbedtls_dhm_context dhm_ctx;
    mbedtls_net_context cfd_ctx;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_dhm_init(&dhm_ctx);
    mbedtls_net_init(&cfd_ctx);
    //设置熵源为伪随机数发生器种子
    if ((mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, indiv_data, strlen(indiv_data))) != 0)
        mbedtls_err(ret);
    //获取服务端公钥
    if ((ret = mbedtls_mpi_read_string(&rsa_ctx.N, 16, rsaN)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&rsa_ctx.E, 16, rsaE)) != 0)
        mbedtls_err(ret);
    //N的长度，用于检验签名的长度
    rsa_ctx.len = (mbedtls_mpi_bitlen(&rsa_ctx.N) + 7) >> 3;
    //客户端通信环境设置
    if ((ret = mbedtls_net_connect(&cfd_ctx, argv[1], argv[2], MBEDTLS_NET_PROTO_TCP)) != 0)
        mbedtls_err(ret);
    //接收服务端数据
    nleft = 0;
    done = 0;
    ret = -1;
    p = buf;
    for (;;)
    {
        //只负责读入缓冲，不作任何处理
        nr = 0;
        if ((nr = mbedtls_net_recv(&cfd_ctx, buf, BUF_SIZE)) < 0)
            mbedtls_err(nr);
        if (!done)
        {
            done = 1;
            for (i = 0; i < 2; i++)
                nleft |= (uint16_t)buf[i] << ((2 - i - 1) << 3);
            len = nleft;
            nleft += 2;     //包括用于存储长度的两个字节
            if (nleft < 3 || nleft > BUF_SIZE)
            {
                mbedtls_fprintf(stderr, "%d less paramenters or invalid buffer length (%d > %d)", __LINE__, nleft, BUF_SIZE);
                goto cleanup;
            }
        }
        nleft -= nr;
        if (nleft == 0)
        {
            ret = 0;
            break;
        }
        p += nr;
    }
    //提取SKE
    p = buf + 2;
    end = p + len;
    if ((ret = mbedtls_dhm_read_params(&dhm_ctx, &p, end)) != 0)    //提取 P G G^Xs mod P
        mbedtls_err(ret);
    p += 2;     //跳过长度判断
    if ((n = (size_t)(end - p)) != rsa_ctx.len)
    {
        mbedtls_fprintf(stderr, "%d Invalid rsa signature size %d != %d\n", __LINE__, n, rsa_ctx.len);
        goto cleanup;
    }
    //重新计算SKE数据哈希，并验签。通过后才会给服务端发送自己的SKE
    if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL)
        mbedtls_err(ret);
    int hsize = mbedtls_md_get_size(md_info);
    if ((ret = mbedtls_sha256_ret(buf + 2, (int)(p - 2 - (buf + 2)), hbuf)) !=0 )
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_pkcs1_verify(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, mbedtls_md_get_type(md_info), hsize, hbuf, p)) != 0)
        mbedtls_err(ret);
    //客户端根据发来的P和G，计算自己的公开值及随机数X
    memset(buf, 0, BUF_SIZE);
    n = dhm_ctx.len;
    if ((ret = mbedtls_dhm_make_public(&dhm_ctx, (int)dhm_ctx.len, buf, n, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
    //发送客户端公开值
    if ((ret = mbedtls_net_send(&cfd_ctx, buf, n)) != (int)n)
        mbedtls_err(ret);
    //计算共享密钥
    memset(buf, 0, BUF_SIZE);
    if ((ret = mbedtls_dhm_calc_secret(&dhm_ctx, buf, BUF_SIZE, &n, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_CLIENT
    mbedtls_mpi_vprint(&dhm_ctx.K, "%d dhm_ctx.K: \n", __LINE__);
#endif
cleanup:
    mbedtls_fprintf(stderr, "ret (%08X)\n", ret);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_rsa_free(&rsa_ctx);
    mbedtls_dhm_free(&dhm_ctx);
    mbedtls_net_free(&cfd_ctx);
    
    return ret;
}