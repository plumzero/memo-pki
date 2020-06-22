#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/dhm.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

#define DEBUG_DHM

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

#define SKEBUF_SIZE 2048
#define SSBUF_SIZE  1024

static const char strP[] = {
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
};
static const char strG[] = {
    "02"
};

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

/**
    功能：根据 P, G 生成Diffile Hellman参数，并进行一些其他函数的测试
        P   prime modulus
        G   generator
    注意：
        1.这里省略了P和G的生成步骤
        2.对于 int mbedtls_dhm_make_params( mbedtls_dhm_context *ctx, int x_size,
                     unsigned char *output, size_t *olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );
            x_size是本地生成的随机数X的字节长度，通常与P的字节长度相同
            output，输出缓冲区，用于紧凑依次存储 P G G^X mod P 三个大数，故务必确保 sizeof(output) >= ∑mbedtls_mpi_size(P G G^X mod P) + 2 × 3 + 1('\0')
            olen 填充后的真实长度
        3.对于事项2中对缓冲区长度的判断，无法对其进行外部检验，故务必要提供足够的缓冲区
        4.对于事项2中缓冲区的存储方式
            [2字节用于存储P字长长度][P字节流][2字节用于存储G字长长度][G字节流][2字节用于存储GX字长长度][G字节流]
        5.mbedtls_dhm_make_public和mbedtls_dhm_read_public函数的用法分别与mbedtls_dhm_make_params和mbedtls_dhm_read_params类似，只不过前者只操作一个公共值
        6.有些地方的传参还是较奇怪的，如mbedtls_dhm_make_public，为了保证不出错，需要结合源码来看
        7.确保 dhm.len >= 64 && dhm.len <= 512
 */
int main()
{
    int ret = 0;
    unsigned char skebuf[SKEBUF_SIZE];      //ske缓冲
    unsigned char ssbuf[SSBUF_SIZE];        //共享密钥缓冲
    unsigned char peergxbuf[SSBUF_SIZE];    //对端存放GX的缓冲区，此缓冲区在本测试中不需要，仅仅是为了生成 dhm_peer_ctx.X 的副产品. 缓冲区长度应不小于 P 字节长度
    size_t skelen, sslen;
    unsigned char *start, *end;
    const char *indiv_data = "Created by C";
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_dhm_context dhm_ctx, dhm_peer_ctx;
    mbedtls_mpi P, G;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_dhm_init(&dhm_ctx);
    mbedtls_dhm_init(&dhm_peer_ctx);
    
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    
    //设置熵源作为伪随机数种子
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)indiv_data, strlen(indiv_data))) != 0)
        mbedtls_err(ret);
    //读取P和G
    if ((ret = mbedtls_mpi_read_string(&P, 16, strP)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&G, 16, strG)) != 0)
        mbedtls_err(ret);
    //local：将P和G导入dhm_ctx
    if ((ret = mbedtls_dhm_set_group(&dhm_ctx, &P, &G)) != 0)
        mbedtls_err(ret);
    //peer：将P和G导入dhm_peer_ctx
    if ((ret = mbedtls_dhm_set_group(&dhm_peer_ctx, &P, &G)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_DHM
    mbedtls_mpi_vprint(&dhm_ctx.P, "%d dhm_ctx.P: \n", __LINE__);
    mbedtls_mpi_vprint(&dhm_ctx.G, "%d dhm_ctx.G: \n", __LINE__);
    mbedtls_mpi_vprint(&dhm_peer_ctx.P, "%d dhm_peer_ctx.P: \n", __LINE__);
    mbedtls_mpi_vprint(&dhm_peer_ctx.G, "%d dhm_peer_ctx.G: \n", __LINE__);
#endif
    //local：生成Diffile-Hellman协议下密钥交换参数(ServerKeyExchange)，即 P G GX  GX=G^XmodP  P G是传入，GX是生成
    if ((ret = mbedtls_dhm_make_params(&dhm_ctx, (int)mbedtls_mpi_size(&dhm_ctx.P), skebuf, &skelen, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
    //peer：生成X和GX，GX在这里不需要，只要X
    if ((ret = mbedtls_dhm_make_public(&dhm_peer_ctx, (int)dhm_peer_ctx.len, peergxbuf, dhm_peer_ctx.len, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_DHM
    mbedtls_mpi_vprint(&dhm_ctx.GX, "%d dhm_ctx.GX: \n", __LINE__);
    mbedtls_mpi_vprint(&dhm_peer_ctx.X, "%d dhm_peer_ctx.X: \n", __LINE__);
#endif
    //下面模拟对端解析密钥交换参数，并计算出共享密钥
    start = skebuf;
    end = skebuf + skelen;      //由于对端并不了解SKE的长度，所以这里最好使用 end = skebuf + sizeof (skebuf)，但为了精确测试，所以就这样了
    if ((ret = mbedtls_dhm_read_params(&dhm_peer_ctx, &start, end)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_DHM
    mbedtls_mpi_vprint(&dhm_peer_ctx.P, "%d dhm_peer_ctx.P: \n", __LINE__);
    mbedtls_mpi_vprint(&dhm_peer_ctx.G, "%d dhm_peer_ctx.G: \n", __LINE__);
    mbedtls_mpi_vprint(&dhm_peer_ctx.GY, "%d dhm_peer_ctx.GY: \n", __LINE__);   //注意，对端将发来的GX作为自己的GY
#endif
    //计算共享密钥 share secret (G^Y)^X mod P 务必确保输出缓冲区长度不小于 P 字节长度
    if ((ret = mbedtls_dhm_calc_secret(&dhm_peer_ctx, ssbuf, SSBUF_SIZE, &sslen, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_DHM
    mbedtls_mpi_vprint(&dhm_peer_ctx.K, "%d dhm_peer_ctx.K: \n", __LINE__);
#endif
cleanup:
    mbedtls_fprintf(stderr, "ret (%08X)\n", ret);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_dhm_free(&dhm_ctx);
    mbedtls_dhm_free(&dhm_peer_ctx);
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&G);
    return ret;
}