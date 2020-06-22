#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

// #define DEBUG_ECP

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

static const char *exponents[] = {
    "000000000000000000000000000000000000000000000001", /* one */
    "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22830", /* N - 1 */
    "5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25", /* random */
    "400000000000000000000000000000000000000000000000", /* one and zeros */
    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* all ones */
    "555555555555555555555555555555555555555555555555", /* 101010... */ 
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
    功能：指定曲线下的基本ecp运算
 */
int main()
{
    int ret = 0;
    size_t i;
    const char *curve_name;
    
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi m;
    
    const mbedtls_ecp_curve_info *curve_info;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&m);
    
    //展示曲线算法
    curve_info = mbedtls_ecp_curve_list();
    for (i = 0; i < 100; i++)
    {
        //不再用箭头->，而是用.运算符
        if (curve_info[i].grp_id != MBEDTLS_ECP_DP_NONE)
            mbedtls_printf("\t%s\n", curve_info[i].name);
        else
            break;
    }
#ifdef DEBUG_ECP
    mbedtls_mpi T;
    mbedtls_mpi_init(&T);
#endif
    //设置secp192r1
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP192R1);
    //设置m为2
    if ((ret = mbedtls_mpi_lset(&m, 2)) != 0)
        mbedtls_err(ret);
    //计算 P = m × grp.G
    if ((ret = mbedtls_ecp_mul(&grp, &P, &m, &grp.G, NULL, NULL)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECP
    mbedtls_mpi_vprint(&m, "%d m: \n", __LINE__);
    mbedtls_mpi_vprint(&grp.G.X, "%d grp.G.X: \n", __LINE__);
    mbedtls_mpi_vprint(&grp.G.Y, "%d grp.G.Y: \n", __LINE__);
    mbedtls_mpi_vprint(&grp.G.Z, "%d grp.G.Z: \n", __LINE__);
    mbedtls_mpi_vprint(&P.X, "%d P.X: \n", __LINE__);
    mbedtls_mpi_vprint(&P.Y, "%d P.Y: \n", __LINE__);
    mbedtls_mpi_vprint(&P.Z, "%d P.Z: \n", __LINE__);
    mbedtls_printf("\n\n");
#endif
    //设置m
    if ((ret = mbedtls_mpi_read_string(&m, 16, exponents[0])) != 0)
        mbedtls_err(ret);
    //计算 R = m × grp.G
    if ((ret = mbedtls_ecp_mul(&grp, &R, &m, &grp.G, NULL, NULL)) != 0)
        mbedtls_err(ret);
#ifdef DEBUG_ECP
    mbedtls_mpi_vprint(&m, "%d m: \n", __LINE__);
    mbedtls_mpi_vprint(&R.X, "%d R.X: \n", __LINE__);
    mbedtls_mpi_vprint(&R.Y, "%d R.Y: \n", __LINE__);
    mbedtls_mpi_vprint(&R.Z, "%d R.Z: \n", __LINE__);
    mbedtls_printf("\n\n");
#endif
    for (i = 0; i < sizeof(exponents) / sizeof(*exponents); i++)
    {
        if ((ret = mbedtls_mpi_read_string(&m, 16, exponents[i])) != 0)
            mbedtls_err(ret);
        if ((ret = mbedtls_ecp_mul(&grp, &R, &m, &grp.G, NULL, NULL)) != 0)
            mbedtls_err(ret);
#ifdef DEBUG_ECP
    mbedtls_mpi_vprint(&m, "%d m: \n", __LINE__);
    mbedtls_mpi_vprint(&R.X, "%d R.X: \n", __LINE__);
    mbedtls_mpi_vprint(&R.Y, "%d R.Y: \n", __LINE__);
    mbedtls_mpi_vprint(&R.Z, "%d R.Z: \n", __LINE__);
    mbedtls_printf("\n");
#endif
    }
    //R=P=2G
    if ((ret = mbedtls_mpi_read_string(&m, 16, exponents[0])) !=0 )
        mbedtls_err(ret);
    if ((ret = mbedtls_ecp_mul(&grp, &R, &m, &P, NULL, NULL)) !=0)
        mbedtls_err(ret);
    for (i = 0; i < sizeof(exponents) / sizeof(*exponents); i++)
    {
        if ((ret = mbedtls_mpi_read_string(&m, 16, exponents[i])) != 0)
            mbedtls_err(ret);
        if ((ret = mbedtls_ecp_mul(&grp, &R, &m, &P, NULL, NULL)) != 0)
            mbedtls_err(ret);
    }

cleanup:
    mbedtls_printf("ret (%08x)\n", ret);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&m);
#ifdef DEBUG_ECP
    mbedtls_mpi_free(&T);
#endif

    return ret;
}