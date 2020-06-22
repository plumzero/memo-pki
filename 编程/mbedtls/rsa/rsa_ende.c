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

#define MBEDTLS_RSA_ENCRYPT_ME      0
#define MBEDTLS_RSA_DECRYPT_ME      1

//调试开关
// #define DEBUG_ENCRYPT
// #define DEBUG_DECRYPT

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
//KEY_LEN的长度与 mbedtls_rsa_context.len 的长度等同
#define KEY_LEN     128

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

#define USAGE   \
    "\n  ./* <mode> <input filename> <output filename>\n" \
    "\n    <mode>: 'e'=encrypt 'd'=decrypt\n" \
    "\n    input file and output file should not use the same name\n" \
    "\n"

/** 
    使用rsa加密或解密注意事项：
    1.mbedtls_rsa_context.len的大小是mbedtls_rsa_context.N的长度，后者的长度与密钥位数相等
    2.加密或解密时，程序从文件中分段读取内容进行操作，每次最大可加解密mbedtls_rsa_context.len
    长度的字节，即假如密钥位数为1024，则最大解密长度为128字节。所以加解密缓冲区的长度的设置应
    不小于mbedtls_rsa_context.len
    3.每次对内容加密时，内容的hex串转为mbedtls_mpi类型后大小应小于mbedtls_rsa_context.N，即
        mbedtls_mpi_read_binary(&T, ibuf, rsa_ctx->len);
        ASSERT(mbedtls_mpi_cmp_mpi(&T, &rsa_ctx->N) < 0);
    本程序每次读取(mbedtls_rsa_context-1)长度字节内容，将加密缓冲首字节设为0，其余使用读取的字
    节进行填充，以此保证满足条件  
    4.如果加密的长度少于mbedtls_rsa_context.len，可以不用进行事项3的操作
    5.如果加密的长度少于mbedtls_rsa_context.len，需要使用填充模式，填充时需要使用随机数发生器
    6.MBEDTLS_RSA_PKCS_V15填充模式
    假设mbedtls_rsa_context.N比特位数为1024，即mbedtls_rsa_context.len=128，
    加密内容长度为100个字节，不足128，设定一个输入buf，对其作如下填充
        [0][MBEDTLS_RSA_CRYPT][25字节的非零随机数填充][0][100字节的加密内容]
    第一个字节填0，第二个字节填加密标志，填充一段非零随机值，填充段以0结尾，其余分配加密内容
    7.MBEDTLS_RSA_PKCS_V21 填充模式
    相比 MBEDTLS_RSA_PKCS_V15, MBEDTLS_RSA_PKCS_V21需要指定一种哈希算法
    如果本程序使用 MBEDTLS_RSA_PKCS_V21 填充模式，只需要将
        mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    替换为
        mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_MD5);
    当然，第3个参数可以选用其他哈希类型
    8.rsa加密 != rsa验签   rsa解密 != rsa签名
*/
/**
 功能：对文件进行rsa加密
 结果：
    PC下对一个28M的文件进行加解密测试
        加密时间测试(15s)
            real    0m15.121s
            user    0m14.858s
            sys     0m0.169s
        解密时间测试(8min)
            real    7m59.919s
            user    7m57.090s
            sys     0m0.392s
    由于rsa采用分段独立加密机制，可以使用多线程进行加解密
 注意：不建议在弱PC上使用此程序对大文件进行加解密操作，容易对磁盘造成损坏
 */
int main(int argc, char * argv[])
{
    int mode, n, flag, ret = 0;
    
    const char *indiv_data = "created by C";    
    FILE *fin = NULL, *fout = NULL;
    off_t filesize, offset;
    
    mbedtls_mpi K;
    mbedtls_rsa_context rsa_ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    //确保输入缓冲与输出缓冲等长
    unsigned char ibuf[KEY_LEN];
    unsigned char obuf[KEY_LEN];
    
    //传参校验与提取
    if (argc < 4)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    mode = strncmp(argv[1], "e", 1) == 0 ? MBEDTLS_RSA_ENCRYPT_ME : 
                (strncmp(argv[1], "d", 1) == 0 ? MBEDTLS_RSA_DECRYPT_ME : -1);
    if(mode != MBEDTLS_RSA_ENCRYPT_ME && mode != MBEDTLS_RSA_DECRYPT_ME)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    if ((fin = fopen(argv[2], "rb")) == NULL)
    {
        mbedtls_fprintf(stderr, "fopen(%s,rb) failed\n", argv[2]);
        goto cleanup;
    }
    if ((fout = fopen(argv[3], "wb+")) == NULL)
    {
        mbedtls_fprintf(stderr, "fopen(%s,wb+) failed\n", argv[3]);
        goto cleanup;
    }
    if ((filesize = lseek(fileno(fin), 0, SEEK_END)) < 0)
    {
        perror("lseek");
        goto cleanup;
    }
    if (fseek(fin, 0, SEEK_SET) < 0)
    {
        mbedtls_fprintf(stderr, "fseek(0,SEEK_SET) failed\n");
        goto cleanup;
    }
    
    mbedtls_mpi_init(&K);
    //用于提取熵源，作为伪随机数发生器的种子
    mbedtls_entropy_init(&entropy);
    //基于aes分组密码算法的伪随机数发生器
    mbedtls_ctr_drbg_init(&ctr_drbg);
    //如果明文太短，这里小于KEY_LEN个字节，设置 MBEDTLS_RSA_PKCS_V15 模式填充
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    // MBEDTLS_RSA_PKCS_V21 填充模式下打开
    // mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_MD5);
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
#if defined(DEBUG_ENCRYPT) || defined(DEBUG_DECRYPT)
    mbedtls_mpi T;
    mbedtls_mpi_init(&T);
#endif
    if (mode == MBEDTLS_RSA_ENCRYPT_ME)
    {
        for (offset = 0; offset < filesize; offset += KEY_LEN - 1)
        {
            n = (filesize - offset > KEY_LEN - 1) ? KEY_LEN - 1 : (int)(filesize - offset);
            //满读
            if (n == KEY_LEN - 1)
            {
                ibuf[0] = 0;        //确保明文段值小于rsa_ctx.N
                if (fread(ibuf + 1, 1, n, fin) != (size_t)n)
                {
                    mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", n);
                    goto cleanup;
                }
                if ((ret = mbedtls_rsa_public(&rsa_ctx, ibuf, obuf)) != 0)
                    mbedtls_err(ret);
            }
            else
            {
                if (fread(ibuf, 1, n, fin) != (size_t)n)
                {
                    mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", n);
                    goto cleanup;
                }
#ifdef DEBUG_DECRYPT
                if (mbedtls_mpi_read_binary(&T, ibuf, n) != 0)
                    fprintf(stderr, "%d error occured\n", __LINE__);
                printMPI("en fread T: ", &T);
#endif
                //注意！这里输入和输出不能使用同一个缓冲
                if ((ret = mbedtls_rsa_pkcs1_encrypt(&rsa_ctx, mbedtls_ctr_drbg_random, 
                                                    &ctr_drbg, MBEDTLS_RSA_PUBLIC, n, ibuf, obuf)) != 0)
                    mbedtls_err(ret);
            }
            if (fwrite(obuf, 1, KEY_LEN, fout) != KEY_LEN)
            {
                mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", rsa_ctx.len);
                goto cleanup;
            }
#ifdef DEBUG_ENCRYPT
            if (mbedtls_mpi_read_binary(&T, obuf, rsa_ctx.len) != 0)
                fprintf(stderr, "%d error occured\n", __LINE__);
            printMPI("fwrite T: ", &T);
#endif
        }
    }
    else
    {
        //对文件长度进行校验
        if (filesize % KEY_LEN != 0)
        {
            mbedtls_fprintf(stderr, "%d filesize(%ld) KEY_LEN(%d)", __LINE__, filesize, KEY_LEN);
            goto cleanup;
        }
        for (offset = 0; offset < filesize; offset += KEY_LEN)
        {
            if (fread(ibuf, 1, KEY_LEN, fin) != (size_t)KEY_LEN)
            {
                mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", KEY_LEN);
                goto cleanup;
            }
#ifdef DEBUG_ENCRYPT
            if (mbedtls_mpi_read_binary(&T, ibuf, rsa_ctx.len) != 0)
                fprintf(stderr, "%d error occured\n", __LINE__);
            printMPI("fread T: ", &T);
#endif
            //未到文件末尾
            if (offset + KEY_LEN != filesize)
            {
                if ((ret = (mbedtls_rsa_private(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, ibuf, obuf))) != 0)
                    mbedtls_err(ret);
                if (fwrite(obuf + 1, 1, KEY_LEN - 1, fout) != (size_t)(KEY_LEN - 1))
                {
                    mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", KEY_LEN - 1);
                    goto cleanup;
                }
            }
            else
            {
                if ((ret = (mbedtls_rsa_pkcs1_decrypt(&rsa_ctx, mbedtls_ctr_drbg_random, 
                                            &ctr_drbg, MBEDTLS_RSA_PRIVATE, (size_t*)&n, ibuf, obuf, sizeof(obuf)))) != 0)
                    mbedtls_err(ret);
                if (fwrite(obuf, 1, n, fout) != (size_t)n)
                {
                    mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", n);
                    goto cleanup;
                }
#ifdef DEBUG_DECRYPT
                if (mbedtls_mpi_read_binary(&T, obuf, n) != 0)
                    fprintf(stderr, "%d error occured\n", __LINE__);
                printMPI("de fwrite T: ", &T);
#endif
            }
        }
    }
    
cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    
    mbedtls_mpi_free(&K);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa_ctx);
    
    return 0;
}