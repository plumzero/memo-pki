#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/bignum.h"

#define mbedtls_printf          printf
#define mbedtls_fprintf         fprintf

static const char strA[] = {
    "EFE021C2645FD1DC586E69184AF4A31E"
    "D5F53E93B5F123FA41680867BA110131"
    "944FE7952E2517337780CB0DB80E61AA"
    "E7C8DDC6C5C6AADEB34EB38A2F40D5E6" 
};

static const char strE[] = {
    "B2E7EFD37075B9F03FF989C7C5051C20"
    "34D2A323810251127E7BF8625A4F49A5"
    "F3E27F4DA8BD59C47D6DAABA4C8127BD"
    "5B5C25763222FEFCCFC38B832366C29E" 
};

static const char strN[] = {
    "0066A198186C18C10B2F5ED9B522752A"
    "9830B69916E535C8F047518A889A43A5"
    "94B6BED27A168D31D4A52F88925AA8F5"
};

static const char strP[] = {
    "602AB7ECA597A3D6B56FF9829A5E8B85"
    "9E857EA95A03512E2BAE7391688D264A"
    "A5663B0341DB9CCFD2C4C5F421FEC814"
    "8001B72E848A38CAE1C65F78E56ABDEF"
    "E12D3C039B8A02D6BE593F0BBBDA56F1"
    "ECF677152EF804370C1A305CAF3B5BF1"
    "30879B56C61DE584A0F53A2447A51E"
};

static const char strQ[] = {
    "256"
    "567336059E52CAE22925474705F39A94"
};

static const char strR[] = {
    "6613F26162223DF488E9CD48CC132C7A"
    "0AC93C701B001B092E4E5B9F73BCD27B"
    "9EE50D0657C77F374E903CDFA4C642" 
};

static const char strS[] = {
    "36E139AEA55215609D2816998ED020BB"
    "BD96C37890F65171D948E9BC7CBAA4D9"
    "325D24D6A3C12710F10A09FA08AB87"
};

static const char strT[] = {
    "003A0AAEDD7E784FC07D8F9EC6E3BFD5"
    "C3DBA76456363A10869622EAC2DD84EC"
    "C5B8A74DAC4D09E03B5E0BE779F2DF61"
};
/**
 存储方式
    "    21C2645FD1DC 586E69184AF4A31E"
    "256567336059E52C AE22925474705F39"
    数组下标    0                   1                   2                   3
    数组元素    [AE22925474705F39]  [256567336059E52C] [586E69184AF4A31E] [21C2645FD1DC]
 */
void print(char * desc, mbedtls_mpi * X)
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

int main(int argc, char * argv[])
{
    int ret = 0;
    mbedtls_mpi A, E, N, P, Q, R, S, T;
    mbedtls_mpi X, Y;

    mbedtls_mpi_init(&A); mbedtls_mpi_init(&E); mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q); mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&S); mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    //将字符串转为十六进制形式的字符串
    if ((ret = mbedtls_mpi_read_string(&A, 16, strA)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_read_string(&E, 16, strE)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_read_string(&N, 16, strN)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_read_string(&P, 16, strP)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_read_string(&Q, 16, strQ)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_read_string(&R, 16, strR)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_read_string(&S, 16, strS)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_read_string(&T, 16, strT)) != 0)
        goto cleanup;
    print("A: ", &A);
    print("E: ", &E);
    print("N: ", &N);
    //基线乘法运算 X为积
    if ((ret = mbedtls_mpi_mul_mpi(&X, &A, &N)) != 0)
        goto cleanup;
    print("P: ", &P);
    print("A * N: ", &X);
    if ((ret = mbedtls_mpi_cmp_mpi(&X, &P)) != 0)
        goto cleanup;
    //除法运算 X为商 Y为余 A为被除数 N为除数
    if ((ret = mbedtls_mpi_div_mpi(&X, &Y, &A, &N)) != 0)
        goto cleanup;
    if (mbedtls_mpi_cmp_mpi(&X, &Q) != 0 || mbedtls_mpi_cmp_mpi(&Y, &R))
    {
        ret = 1;
        goto cleanup;
    }
    print("A / N: ", &X);
    print("Q: ", &Q);
    print("A % N: ", &Y);
    print("R: ", &R);
    //模幂运算 X = A^E mod N
    if ((ret = mbedtls_mpi_exp_mod(&X, &A, &E, &N, NULL)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_cmp_mpi(&X, &S)) != 0)
        goto cleanup;
    print("A^E mod N: ", &X);
    print("S: ", &S);
    //模的逆运算 X = A^-1 mod N
    if ((ret = mbedtls_mpi_inv_mod(&X, &A, &N)) != 0)
        goto cleanup;
    if ((ret = mbedtls_mpi_cmp_mpi(&X, &T)) != 0)
        goto cleanup;
    print("A^-1 mod N: ", &X);
    print("T: ", &T);

cleanup:
    mbedtls_printf("ret (%08X)\n", ret);
    
    mbedtls_mpi_free(&A); mbedtls_mpi_free(&E); mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q); mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&S); mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    
    return ret;
}