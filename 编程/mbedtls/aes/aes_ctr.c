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
    "NONCE9UmBIPZ3kCH7x+9NpJZU0BlulpH"
};
//调用这个会自动增加1 nonctr_one(a, lowidx, (int)(sizeof(a)/sizeof(a[1])))
int nonctr_one(unsigned char a[], int lowidx, int upidx)
{
    if (lowidx > upidx)
        return -1;
    if ((unsigned char)(a[upidx] ^ 0xFF) != 0)
    {
        ++a[upidx];
        return 0;
    }
    else
    {
        a[upidx] ^= 0xFF;
        return nonctr_one(a, lowidx, upidx - 1);
    }
}

/**
 可以运用于实际
 这里保存未加密的iv
 事实上，如果不考虑明文长度的因素（可能无法被16整除），加密和解密实际使用同一个流程
 可使用 Beyond Compare 工具与 aes_ofb.c 比较不同
 */
int main(int argc, char * argv[])
{
    int i, n, mode, ret = 0;
    unsigned char lastn;
    unsigned char key[32];
    unsigned char buf[16];
    unsigned char nonctr[16];
    unsigned char stmblk[16];
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
    //设置加密密钥
    if((ret = mbedtls_aes_setkey_enc(&aes_ctx, key, keybits)) != 0)
        goto exit;
    //加密，理论上可以加密 2^64 * 16 字节的文件
    if (mode == MBEDTLS_AES_ENCRYPT)
    {
        //设置nonctr，将前8个字节作为nonce，固定不变；后8个字节作为分组序号，从0开始逐次累加
        memset(nonctr, 0, 16);
        memcpy(nonctr, random_ + 64, 8);
        //文件长度与16之模，其值存入nonctr下标为7的位置，这里只保存nonctr的nonce部分
        lastn = (unsigned char)(filesize & 0x0F);
        nonctr[7] = (unsigned char)(nonctr[7] & 0xF0 | lastn);
        if(fwrite(nonctr, 1, 8, fout) != 8)
        {
            mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", 8);
            goto exit;
        }
        //ctr模式加密
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
            //对nonctr进行加密，生成流stmblk
            mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, nonctr, stmblk);
            //流stmblk与明文异或，生成段加密缓冲，写入文件
            for (i = 0; i < 16; i++)
                buf[i] = (unsigned char)(buf[i] ^ stmblk[i]);
            if(fwrite(buf, 1, 16, fout) != 16)
            {
                mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", 16);
                goto exit;
            }
            //分组序号递增1
            nonctr_one(nonctr, 8, 15);  
        }
    }
    //解密
    else
    {   
        //读取密文首部，设置nonctr
        if(fread(nonctr, 1, 8, fin) != 8)
        {
            mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", 8);
            goto exit;
        }
        lastn = (unsigned char)(nonctr[7] & 0x0F);
        memset(nonctr + 8, 0, 8);
        //真正的密文长度
        filesize -= 8;
        //确保密文长度模16为0
        if((filesize & 0x0F) != 0)
        {
            mbedtls_fprintf(stderr, "File size not a multiple of 16.\n");
            goto exit;
        }
        //ctr模式解密
        for(offset = 0; offset < filesize; offset += 16)
        {
            //从密文中取出16个字符，称为待解密段
            if(fread(buf, 1, 16, fin) != 16)
            {
                mbedtls_fprintf(stderr, "fread(%d bytes) failed\n", 16);
                goto exit;
            }
            //对nonctr进行加密，生成流stmblk
            mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, nonctr, stmblk);
            //加密后的nonctr与密文异或，生成段解密缓冲，写入文件，
            for(i = 0; i < 16; i++)
                buf[i] = (unsigned char)(buf[i] ^ stmblk[i]);
            //最后一个段加密缓冲
            n = (offset + 16 == filesize && (int)lastn > 0) ? (int)lastn : 16;
            if(fwrite(buf, 1, n, fout) != (size_t)n)
            {
                mbedtls_fprintf(stderr, "fwrite(%d bytes) failed\n", n);
                goto exit;
            }
            //分组序号递增1
            nonctr_one(nonctr, 8, 15);  
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
    memset(nonctr, 0, sizeof(nonctr));
    memset(stmblk, 0, sizeof(stmblk));
    return ret;
}
