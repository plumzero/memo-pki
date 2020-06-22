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

#define DEBUG_SERVER

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

#define USAGE   \
    "\n  ./* <port>\n" \
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
//服务端密钥对
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
static const char rsaD[] = {
    "3FF2331A2FE085830F035A15B4CDDDB4E7F048D951DB7C78062FA0F5C58B1691"
    "F28978E2A936632887EA2D3B7E790197CEE2E893826BAE48EC5DB7F2E400973D"
    "8FBEFA296ED6D3499BC59FDB27C0876C5E180625FD40E4E935D4819994148356"
    "13258A6100F0526AFA056B064F2AF7409E5E9B50D15307E62EDCEFEDACB3B148"
    "6E479010C53A4A57DA5FF7936461FD1E65ACD77A51BEFAE1B68E14D278861486"
    "A93EB7D3247F8B98DD2D6B1927DFDD760D17D4D6C9B96E92BDD1C78E3013C291"
    "859313F5CE58C2F500A18B57F7C3BB057D575642A5717050C077F8207C0FA526"
    "2B0D0C9DFC8F7642434CE1C6756B6CD898687A91D942AA62C32EE1E7C739E6C9"
};
static const char rsaP[] = {
    "C66C126F1E12AA8A32FABB9A2AD89BEA2D93299D06FEAF2DD5BE6641D4F1141E"
    "B2F11AA379D43D7B75F7CB72239E45990F6037AB08E8BC6C0D45CF14157D8385"
    "79F39C021246B8229CEC619B721F4484142FD09A8F811DFDB5C20711567BEB87"
    "CB50C7FCAD56B68B27D5165D9AB72FFEB3FAB93DF98962868F979BE4A3396DEB"
};
static const char rsaQ[] = {
    "C4F67C62528EB2E1FD8314E409C9F4C3F163BC8254588D0DC69EDBDC8E74D46A"
    "9E35E2B48ACBCF34603BE96D8C5A43ADA79EEADF47529D21476982FFDBDFCAEA"
    "EC81B2AEA3D189A945F211F2585B1C1E2699ECBC97E0A39B425C520F24AD3456"
    "C3573691827C6BFE4F6EF167A0A2A6B91FB624F456654CC1AEF1927B7906D899"
};
//通信双方共享的Diffle-Hellman参数
static const char dhmP[] = {
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
};
static const char dhmG[] = {
    "02"
};
/**
    功能：
        Diffile-Hellman协议下的密钥参数交换 服务端
    注意事项：
        1.本程序未做详细传参检验，传入参数需严格执行
        2.buf缓冲区内容格式
            [两字节用于存储总长度][SKE][两字节用于存储SKE签名长度][SKE签名]                
 */
int main(int argc, char *argv[])
{
    int i, ret = 0;
    FILE *f;
    unsigned char buf[BUF_SIZE];    //ske + sig，确保足够大 BUF_SIZE > ske长度 + rsa密钥长度 + 其他一些小东西
    unsigned char hbuf[128];
    size_t skelen, len;
    const char *indiv_data = "Created by C";
    
    const mbedtls_md_info_t *md_info = NULL;
    
    if (argc < 2)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_net_context lfd_ctx, cfd_ctx;       //listening fd 和 connected fd
    mbedtls_rsa_context rsa_ctx;
    mbedtls_dhm_context dhm_ctx;
    
    mbedtls_mpi N, P, Q, D, E;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_net_init(&lfd_ctx);
    mbedtls_net_init(&cfd_ctx);
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_dhm_init(&dhm_ctx);
    
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D); mbedtls_mpi_init(&E);
    
    //利用熵源作为伪随机数种子
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)indiv_data, strlen(indiv_data))) != 0)
        mbedtls_err(ret);
    //服务端构造自己的rsa密钥对
    if ((ret = mbedtls_mpi_read_string(&N, 16, rsaN)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&P, 16, rsaP)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&Q, 16, rsaQ)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&D, 16, rsaD)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&E, 16, rsaE)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_import(&rsa_ctx, &N, &P, &Q, &D, &E)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_complete(&rsa_ctx)) != 0)
        mbedtls_err(ret);
    //获取 dhm 的 P G
    if ((ret = mbedtls_mpi_read_string(&dhm_ctx.P, 16, dhmP)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&dhm_ctx.G, 16, dhmG)) != 0)
        mbedtls_err(ret);
    //服务端通信环境设置，阻塞态测试
    if ((ret = mbedtls_net_bind(&lfd_ctx, NULL, argv[1], MBEDTLS_NET_PROTO_TCP)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_net_accept(&lfd_ctx, &cfd_ctx, NULL, 0, NULL)) != 0)
        mbedtls_err(ret);
    //服务端生成自己的SKE，存到buf中
    if ((ret = mbedtls_dhm_make_params(&dhm_ctx, (int)mbedtls_mpi_size(&dhm_ctx.P), buf + 2, &skelen, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
    //使用RSA算法对SKE签名
    //选定哈希算法并哈希SKE
    if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL)
        mbedtls_err(ret);
    int hsize = mbedtls_md_get_size(md_info);
    if ((ret = mbedtls_sha256_ret(buf + 2, skelen, hbuf)) !=0 )
        mbedtls_err(ret);
    //紧随SKE，存储签名长度 网络字节序存储
    for (i = 0; i < 2; i++)
        buf[skelen + 2 + i] = (unsigned char)((uint16_t)rsa_ctx.len >> ((2 - i - 1) << 3));
    //签名
    if ((ret = mbedtls_rsa_pkcs1_sign(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, mbedtls_md_get_type(md_info), hsize, hbuf, buf + skelen + 2 + 2)) != 0)
        mbedtls_err(ret);
    //计算总长度存储
    len = skelen + 2 + rsa_ctx.len;
    for (i = 0; i < 2; i++)
        buf[i] = (unsigned char)((uint16_t)len >> ((2 - i - 1) << 3));
    //向客户端发送buf
    if ((ret = mbedtls_net_send(&cfd_ctx, buf, len + 2)) != len + 2)
        mbedtls_err(ret);
    //获取客户端的GX作为自己的GY
    memset(buf, 0, BUF_SIZE);
    len = dhm_ctx.len;  //GX的字节长度与P相同
    if ((ret = mbedtls_net_recv(&cfd_ctx, buf, len)) != (int)len)
        mbedtls_err(ret);
    if ((ret = mbedtls_dhm_read_public(&dhm_ctx, buf, dhm_ctx.len)) != 0)
            mbedtls_err(ret);
    //服务端计算共享密钥
    len = 0;
    if ((ret = mbedtls_dhm_calc_secret(&dhm_ctx, buf, BUF_SIZE, &len, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_SERVER
    mbedtls_mpi_vprint(&dhm_ctx.K, "%d dhm_ctx.K: \n", __LINE__);
#endif
cleanup:
    mbedtls_fprintf(stderr, "ret (%08X)\n", ret);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_net_free(&lfd_ctx);
    mbedtls_net_free(&cfd_ctx);
    mbedtls_rsa_free(&rsa_ctx);
    mbedtls_dhm_free(&dhm_ctx);
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D); mbedtls_mpi_free(&E);
    
    return ret;
}