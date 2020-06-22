#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/aes.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

#define USAGE   \
    "\n  ./* <keybits> [string]\n" \
    "\n    <keybits>: Supported aes key bits length: 128 192 256\n" \
    "\n    [string]: optional\n" \
    "\n"
const static char random_[] = {
    "KEY9as5NidWWVbZWQ3lud6qEyEB64IAp"
};

//此加密未使用任何模式，只作测试或流程参考，不能用于实际
int main(int argc, char * argv[])
{
    int i, ret = 0;
    unsigned char key[32];      //虽然密钥位数以二进制位数为准，但在实际使用中均会以字符串表示
    unsigned char plain[16];    //一次性最多只能加密16位
    unsigned char cipher[16];
    size_t keybits, ilen;
    
    keybits = argv[1] ? atoi(argv[1]) : 256;        //如果这样可能会运行失败  ./程序名
    if (!(keybits == 128 || keybits == 192 || keybits == 256))
    {
        mbedtls_printf(USAGE);
        return -1;
    }
    strncpy(key, random_, keybits / 8);
    
    argv[2] ? strcpy(plain, argv[2]) : strcpy(plain, "Hello World!");
    
    mbedtls_aes_context aes_ctx;
    
    mbedtls_aes_init(&aes_ctx);
    
    //加密
    if((ret = mbedtls_aes_setkey_enc(&aes_ctx, key, keybits)) != 0)
        goto exit;
    
    memset(cipher, 0, sizeof(cipher));
    mbedtls_aes_encrypt(&aes_ctx, plain, cipher);
    
    mbedtls_printf("加密：\n\t");
    for(i = 0; i < 16; i++)
    {
        mbedtls_printf("%02X ", cipher[i]);
    }
    mbedtls_printf("\n");
    
    //解密
    if ((ret = mbedtls_aes_setkey_dec(&aes_ctx, key, keybits)) != 0)
        goto exit;
    
    memset(plain, 0, sizeof(plain));
    mbedtls_aes_decrypt(&aes_ctx, cipher, plain);
    
    mbedtls_printf("解密:\n\t%s\n", plain);
    
exit:
    mbedtls_aes_free(&aes_ctx);
    return 0;
}
