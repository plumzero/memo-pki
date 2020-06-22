#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/aes.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define USAGE   \
    "\n  ./* <mode> <keybits> <input filename> <output filename> [iv step]\n" \
    "\n    <mode>: e or d\n" \
    "\n    <keybits>: select one from [ 128, 192, 256]\n" \
    "\n    input file and output file should not use the same name\n" \
    "\n    [iv step]: set encrypt iv steps, only support 16 for the time being\n" \
    "\n"
const static char random_[] = {
    "KEY9as5NidWWVbZWQ3lud6qEyEB64IAp"
    "IVq3GXR7+5hkbdgRiDkt/rlD7WPEtdwE"
};
/**
 不建议运用于实际
 这里保存未加密的iv
 经过简单测试，设置加密步长并未提高加密效率，不建议跳步，因为这不是cfb加密模式的标准
 事实上，如果不考虑明文长度的因素（可能无法被16整除），加密和解密实际使用同一个流程
 可使用 Beyond Compare 工具与 aes_cbc.c 比较不同
 */
int main(int argc, char * argv[])
{
    int i, n, k, step, mode, ret = 0;
    char lastn;
    unsigned char key[32];
    unsigned char buf[16];
    unsigned char iv[16];
    size_t keybits, ilen;
    off_t filesize, offset;
    mbedtls_aes_context aes_ctx;
    FILE *fin = NULL, *fout = NULL;
    
    if (argc < 5)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    mode = strncmp(argv[1], "e", 1) == 0 ? MBEDTLS_AES_ENCRYPT : 
                (strncmp(argv[1], "d", 1) == 0 ? MBEDTLS_AES_DECRYPT : -1);
    if(mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    
    keybits = atoi(argv[2]);
    if(keybits != 128 && keybits != 192 && keybits != 256)
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    memcpy(key, random_, keybits / 8);
    
    if(strcmp(argv[3], argv[4]) == 0)
    {
        mbedtls_fprintf(stderr, "plain and cipher filenames must differ\n");
        return -1;
    }
    
    if((fin = fopen(argv[3], "rb")) == NULL )
    {
        mbedtls_fprintf(stderr, "fopen(%s,rb) failed\n", argv[3]);
        goto exit;
    }
    
    if((fout = fopen(argv[4], "wb+")) == NULL )
    {
        mbedtls_fprintf(stderr, "fopen(%s,wb+) failed\n", argv[4]);
        goto exit;
    }
    
    if((filesize = lseek(fileno(fin), 0, SEEK_END)) < 0)
    {
        perror( "lseek" );
        goto exit;
    }
    if(fseek(fin, 0, SEEK_SET) < 0)
    {
        mbedtls_fprintf(stderr, "fseek(0,SEEK_SET) failed\n");
        goto exit;
    }
    //是否开启iv加密步长
    step = argv[5] ? 1 : 0;
    
    mbedtls_aes_init(&aes_ctx);
    
    memset(buf, 0, sizeof(buf));
    //设置加密密钥
    if((ret = mbedtls_aes_setkey_enc(&aes_ctx, key, keybits)) != 0)
        goto exit;
    k = 0;
    //加密
    if (mode == MBEDTLS_AES_ENCRYPT)
    {
        //获取iv
        memcpy(iv, random_ + 32, 16);
        //文件长度与16之模，与iv混合后写入文件首部
        lastn = (char)(filesize & 0x0F);
        iv[15] = (unsigned char)(iv[15] & 0xF0 | lastn);
        if(fwrite(iv, 1, 16, fout) != 16)
        {
            mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", 16);
            goto exit;
        }
        //cfb128模式加密
        for(offset = 0; offset < filesize; offset += 16)
        {
            n = (filesize - offset > 16) ? 16 : (int)(filesize - offset);
            if(fread(buf, 1, n, fin) != (size_t)n)
            {
                mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", n);
                    goto exit;
            }
            //最后一个加密段不足16字符，一般使用文件长度模16的值填充
            if(n != 16)
                memset(buf + lastn, lastn, 16 - lastn);
            //对iv进行加密
            if(step && k == 0)
                mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
            //加密后的iv与明文异或，生成段加密缓冲，写入文件，段加密缓冲也作为新的iv
            for (i = 0; i < 16; i++)
                iv[i] = buf[i] = (unsigned char)(buf[i] ^ iv[i]);
            if(fwrite(buf, 1, 16, fout) != 16)
            {
                mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", 16);
                goto exit;
            }
            if (step)
                k = (k + 1) & 0x0F;
        }
    }
    //解密
    else
    {   
        unsigned char tmp[16] = { 0 };
        //读取密文首部
        if(fread(iv, 1, 16, fin) != 16)
        {
            mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", 16);
            goto exit;
        }
        lastn = (char)(iv[15] & 0x0F);
        //真正的密文长度
        filesize -= 16;
        //确保密文长度模16为0
        if((filesize & 0x0F) != 0)
        {
            mbedtls_fprintf(stderr, "File size not a multiple of 16.\n");
            goto exit;
        }
        //cfb128模式解密
        for(offset = 0; offset < filesize; offset += 16)
        {
            //从密文中取出16个字符，称为待解密段
            if(fread(buf, 1, 16, fin) != 16)
            {
                mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", 16);
                goto exit;
            }
            //备份段加密缓冲，作为之后新的iv
            memcpy(tmp, buf, 16);
            //对iv进行加密
            if(step && k == 0)
                mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
            //加密后的iv与密文异或，生成段解密缓冲，写入文件，
            for(i = 0; i < 16; i++)
                buf[i] = (unsigned char)(buf[i] ^ iv[i]);
            //最后一个段加密缓冲
            n = (offset + 16 == filesize && (int)lastn > 0) ? (int)lastn : 16;
            if(fwrite(buf, 1, n, fout) != (size_t)n)
            {
                mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", n);
                goto exit;
            }
            //将备份的密文段缓冲作为新的iv
            memcpy(iv, tmp, 16);
            if (step)
                k = (k + 1) & 0x0F;
        }
    }
    
exit:
    if(fin) fclose(fin);
    if(fout) fclose(fout);
    for( i = 0; i < (unsigned int) argc; i++ )
        memset( argv[i], 0, strlen( argv[i] ) );
    mbedtls_aes_free(&aes_ctx);
    memset(key, 0, sizeof(key));
    memset(buf, 0, sizeof(buf));
    memset(iv, 0, sizeof(iv));
    return ret;
}
