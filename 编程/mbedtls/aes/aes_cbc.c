#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/aes.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define USAGE   \
    "\n  ./* <mode> <keybits> <input filename> <output filename>\n" \
    "\n    <mode>: e or d\n" \
    "\n    <keybits>: select one from [ 128, 192, 256]\n" \
    "\n    input file and output file should not use the same name\n" \
    "\n"
const static char random_[] = {
    "KEY9as5NidWWVbZWQ3lud6qEyEB64IAp"
    "IVq3GXR7+5hkbdgRiDkt/rlD7WPEtdwE"
};
//可以运用于实际
//可使用 Beyond Compare 工具与 aes_ecb.c 比较不同
int main(int argc, char * argv[])
{
    int i, n, mode, ret = 0;
    char lastn;
    unsigned char key[32];
    unsigned char buf[16];
    unsigned char iv[16];
    size_t keybits, ilen;
    off_t filesize, offset;
    mbedtls_aes_context aes_ctx;
    FILE *fin = NULL, *fout = NULL;
    
    if (argc != 5)
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
        
    mbedtls_aes_init(&aes_ctx);
    
    memset(buf, 0, sizeof(buf));
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
        //设置加密密钥
        if((ret = mbedtls_aes_setkey_enc(&aes_ctx, key, keybits)) != 0)
            goto exit;
        //cbc模式加密
        for (offset = 0; offset < filesize; offset += 16)
        {
            n = (filesize - offset > 16) ? 16 : (int)(filesize - offset);
            if (fread(buf, 1, n, fin) != (size_t)n)
            {
                mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", n );
                    goto exit;
            }
            //最后一个加密段不足16字符，一般使用文件长度模16的值填充
            if (n != 16)
                memset(buf + lastn, lastn, 16 - lastn);
            //与iv异或操作
            for (i = 0; i < 16; i++)
                buf[i] = (unsigned char)(buf[i] ^ iv[i]);
            //生成段加密缓冲，写入密文
            mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, buf, buf);
            if(fwrite(buf, 1, 16, fout) != 16)
            {
                mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
                goto exit;
            }
            //将段加密缓冲作为新的iv
            memcpy(iv, buf, 16);
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
        //设置解密密钥
        if ((ret = mbedtls_aes_setkey_dec(&aes_ctx, key, keybits)) != 0)
            goto exit;
        //cbc模式解密
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
            //生成段解密缓冲，写入文件
            mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_DECRYPT, buf, buf);
            //与iv异或操作
            for(i = 0; i < 16; i++)
                buf[i] = (unsigned char)(buf[i] ^ iv[i]);
            //最后一个段加密缓冲
            n = (offset + 16 == filesize && (int)lastn > 0) ? (int)lastn : 16;
            if(fwrite(buf, 1, n, fout) != (size_t)n)
            {
                mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", n );
                goto exit;
            }
            memcpy(iv, tmp, 16);
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
