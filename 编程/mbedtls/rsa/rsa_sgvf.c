#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

#define MBEDTLS_RSA_SIGN_ME     0
#define MBEDTLS_RSA_VERIFY_ME   1

//调试开关
// #define DEBUG_SIGN
// #define DEBUG_VERIFY

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define KEY_LEN     128

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

#define USAGE   \
    "\n  ./* <mode> <sign file path> <io file>\n" \
    "\n    <mode>: 's'=sign 'v'=verify\n" \
    "\n    <io file>: write or read the signature\n" \
    "\n"
/**
 功能：对文件进行rsa签名

    如果本程序使用 MBEDTLS_RSA_PKCS_V21 填充模式，只需要将
        mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    替换为
        mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_MD5);
    当然，第3个参数可以选用其他哈希类型
 */
int main(int argc, char * argv[])
{
    int i, c, mode, ret = 0;
    FILE *f;
    
    const char *indiv_data = "created by C";    
    char path[1024] = { 0 };
    
    mbedtls_mpi K;
    mbedtls_rsa_context rsa_ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    
    const mbedtls_md_info_t *md_info = NULL;

    unsigned char hbuf[128];
    unsigned char sbuf[KEY_LEN] = { 0 };    //签名的长度与mbedtls_rsa_context.len相等，sbuf长度需至少为KEY_LEN
    
    //传参校验与提取
    if (argc < 4)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    mode = strncmp(argv[1], "s", 1) == 0 ? MBEDTLS_RSA_SIGN_ME : 
                (strncmp(argv[1], "v", 1) == 0 ? MBEDTLS_RSA_VERIFY_ME : -1);
    if(mode != MBEDTLS_RSA_SIGN_ME && mode != MBEDTLS_RSA_VERIFY_ME)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    strcpy(path, argv[2]);
    
    if (mode == MBEDTLS_RSA_SIGN_ME)
    {
        if ((f = fopen(argv[3], "wb+")) == NULL)
        {
            mbedtls_fprintf(stderr, "fopen(%s,wb+) failed\n", argv[3]);
            goto cleanup;
        }
    }
    else
    {
        if ((f = fopen(argv[3], "rb")) == NULL)
        {
            mbedtls_fprintf(stderr, "fopen(%s,rb) failed\n", argv[3]);
            goto cleanup;
        }
    }
        
    mbedtls_mpi_init(&K);
    //用于提取熵源，作为伪随机数发生器的种子
    mbedtls_entropy_init(&entropy);
    //基于aes分组密码算法的伪随机数发生器
    mbedtls_ctr_drbg_init(&ctr_drbg);
    //如果明文太短，这里小于KEY_LEN个字节，设置 MBEDTLS_RSA_PKCS_V15 模式填充
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_MD5);
    //利用熵源设置伪随机数种子
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *)indiv_data, strlen(indiv_data))) != 0)
        goto cleanup;
    //完成大数导入 N, P, Q的关系 N=P×Q
    if ((ret = mbedtls_mpi_read_string(&K, 16, RSA_N)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_import(&rsa_ctx, &K, NULL, NULL, NULL, NULL)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&K, 16, RSA_P)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_import(&rsa_ctx, NULL, &K, NULL, NULL, NULL)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&K, 16, RSA_Q)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_import(&rsa_ctx, NULL, NULL, &K, NULL, NULL)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&K, 16, RSA_D)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_import(&rsa_ctx, NULL, NULL, NULL, &K, NULL)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_mpi_read_string(&K, 16, RSA_E)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_import(&rsa_ctx, NULL, NULL, NULL, NULL, &K)) != 0)
        mbedtls_err(ret);
    if ((ret = mbedtls_rsa_complete(&rsa_ctx)) != 0)
        mbedtls_err(ret);
    //公私钥检测
    if ((ret = mbedtls_rsa_check_pubkey(&rsa_ctx)) != 0 || (ret = mbedtls_rsa_check_privkey(&rsa_ctx)) != 0)
        mbedtls_err(ret);
    //设置哈希算法为sha256
    if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL)
        goto cleanup;
    //哈希长度
    int hsize = mbedtls_md_get_size(md_info);
    //生成哈希
    if ((ret = mbedtls_md_file(md_info, path, hbuf)) !=0)
        mbedtls_err(ret);
#if defined(DEBUG_SIGN) || defined(DEBUG_VERIFY)
    //打印哈希
    mbedtls_printf("%s: ", path);
    for (i = 0; i < hsize; i++)
        mbedtls_printf("%02x", hbuf[i]);
    mbedtls_printf("\n");
#endif
    if (mode == MBEDTLS_RSA_SIGN_ME)
    {
        //对哈希签名 第2、3个参数可设置为NULL，对签名结果不会有影响
        if ((ret = mbedtls_rsa_pkcs1_sign(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, 
                                    mbedtls_md_get_type(md_info), hsize, hbuf, sbuf)) != 0)
            mbedtls_err(ret);
        //格式化写入文件
        for( i = 0; i < rsa_ctx.len; i++ )
            mbedtls_fprintf(f, "%02X%s", sbuf[i], (i + 1) % 16 == 0 ? "\r\n" : " ");
#ifdef DEBUG_SIGN
        //打印签名
        mbedtls_printf("%s pkcs1_v15 sign:\n", path);
        for(i = 0; i < rsa_ctx.len; i++)
        {
            mbedtls_fprintf(stdout, "0x%02X ", sbuf[i]);
            if ((i & 0x0F ^ 0x0F) == 0)
                mbedtls_fprintf(stdout, "\n");
        }
#endif
        mbedtls_printf("created the signature of %s\n", path);
    }
    else
    {
        //格式化读取文件
        i = 0;
        while(fscanf(f, "%02X", &c) > 0 && i < rsa_ctx.len)
            sbuf[i++] = (unsigned char)c;
#ifdef DEBUG_VERIFY
        for (i = 0; i < rsa_ctx.len; i++)
        {
            mbedtls_fprintf(stdout, "0x%02X ", sbuf[i]);
            if ((i & 0x0F ^ 0x0F) == 0)
                mbedtls_fprintf(stdout, "\n");
        }
#endif
        if((ret = mbedtls_rsa_pkcs1_verify(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                  mbedtls_md_get_type(md_info), hsize, hbuf, sbuf)) != 0)
            mbedtls_err(ret);
        mbedtls_printf("the signature is valid\n");
    }
    
cleanup:
    fclose(f);
    mbedtls_mpi_free(&K);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa_ctx);
    
    return 0;
}