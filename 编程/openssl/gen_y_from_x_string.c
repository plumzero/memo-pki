
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/rand.h>

#define STOP_IT_IF_ERROR(assertion, variable, format, ...)      \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, "%d %s ", __LINE__, #variable);     \
            fprintf(stderr, format, ##__VA_ARGS__);             \
            fprintf(stderr, "\n");                              \
            goto cleanup;                                       \
        }                                                       \
    } while (0)

/**
  编译环境：
    debian 6 (Corp)
  编译命令：
    gcc -g -O0 `pkg-config --cflags --libs libcrypto` gen_y_from_x_string.c -o gen_y_from_x_string -DKOAL_SSL_EXTENSION
  涉及的主要函数：
    EC_POINT_set_affine_coordinates_GFp
  说明：
    1. 本测试不涉及私钥，即不涉及 EC_KEY_* 类函数。
    2. 通常，公私钥以串的形式进行展示。
       导出公钥时，调用 EC_POINT_get_affine_coordinates_GFp 获取公钥仿射坐标点(x, y)，之后对 x, y 分别调用 BN_bn2bin_ex 
       获取公钥串(szX, szY)；
       将公钥与椭圆曲线关联时，分别调用 BN_bin2bn 将公钥串(szX, szY)，转换为仿射坐标点(x, y)，之后调用
       EC_POINT_set_affine_coordinates_GFp 函数将仿射坐标点与椭圆关联。
    3. 可通过 EC_POINT_is_on_curve 验证公钥点是否在某椭圆曲线上。  
 */

static const unsigned char x_only_s[32] = {
                0x66, 0xE0, 0x02, 0xD6, 0x1C, 0x87, 0x1B, 0x3F, 0xCD, 0x18, 0xD6, 0x05, 0x41, 0xED, 0x47, 0x7A,
                0x7F, 0x79, 0x48, 0xBF, 0x27, 0x8E, 0x28, 0x5A, 0x44, 0x02, 0x70, 0x73, 0x8F, 0x8E, 0x09, 0x08
                                        };
static const unsigned char y_0_s[32] = {
                0x4D, 0xBF, 0x6D, 0x37, 0xFD, 0x0B, 0x0B, 0x4A, 0x10, 0x84, 0xCF, 0x92, 0x03, 0x66, 0x1A, 0xAD,
                0x1C, 0x61, 0x8F, 0x8C, 0x0F, 0x52, 0x99, 0x8C, 0x4C, 0xFE, 0xB5, 0xD9, 0xBC, 0x41, 0x0D, 0x50
                                     };

static const unsigned char y_1_s[32] = {
                0xB2, 0x40, 0x92, 0xC7, 0x02, 0xF4, 0xF4, 0xB5, 0xEF, 0x7B, 0x30, 0x6D, 0xFC, 0x99, 0xE5, 0x52,
                0xE3, 0x9E, 0x70, 0x72, 0xF0, 0xAD, 0x66, 0x74, 0xB3, 0x01, 0x4A, 0x26, 0x43, 0xBE, 0xF2, 0xAF
                                     };

int main()
{
    int ret = -1;   
    BIGNUM *x = NULL;
    BIGNUM *y_0 = NULL;
    BIGNUM *y_1 = NULL;
    EC_GROUP *pstEcGroup_0 = NULL;
    EC_GROUP *pstEcGroup_1 = NULL;
    EC_POINT *pstEcPoint_0 = NULL;
    EC_POINT *pstEcPoint_1 = NULL;
    size_t i;
    
    // 公钥 x
    x = BN_new();
    x = BN_bin2bn(x_only_s, 32, NULL);
    // 公钥 y 0
    y_0 = BN_new();
    y_0 = BN_bin2bn(y_0_s, 32, NULL);
    pstEcGroup_0 = EC_GROUP_new_by_curve_name(NID_CN_GM_ECC);
    STOP_IT_IF_ERROR(NULL == pstEcGroup_0, pstEcGroup_0, "EC_GROUP_new_by_curve_name failed");
    pstEcPoint_0 = EC_POINT_new(pstEcGroup_0);
    STOP_IT_IF_ERROR(NULL == pstEcPoint_0, pstEcPoint_0, "EC_POINT_new failed");
    // 设置仿射坐标
    ret = EC_POINT_set_affine_coordinates_GFp(pstEcGroup_0, pstEcPoint_0, x, y_0, NULL);
    STOP_IT_IF_ERROR(1 != ret, pstEcPoint_0, "EC_POINT_set_affine_coordinates_GFp failed");
    // 重构后的点比较 主要判断重构点是否在椭圆曲线上
    if (1 == EC_POINT_is_on_curve(pstEcGroup_0, pstEcPoint_0, NULL)) 
    {
        fprintf(stdout, "====== 公钥点在椭圆曲线上! ======\n");
    }
    else
    {
        fprintf(stdout, "×××××× 公钥点不在椭圆曲线上! ××××××\n");
    }
    
    // 公钥 y 1
    y_1 = BN_new();
    y_1 = BN_bin2bn(y_1_s, 32, NULL);
    pstEcGroup_1 = EC_GROUP_new_by_curve_name(NID_CN_GM_ECC);
    STOP_IT_IF_ERROR(NULL == pstEcGroup_1, pstEcGroup_1, "EC_GROUP_new_by_curve_name failed");
    pstEcPoint_1 = EC_POINT_new(pstEcGroup_1);
    STOP_IT_IF_ERROR(NULL == pstEcPoint_1, pstEcPoint_1, "EC_POINT_new failed");
    // 设置仿射坐标
    ret = EC_POINT_set_affine_coordinates_GFp(pstEcGroup_1, pstEcPoint_1, x, y_1, NULL);
    STOP_IT_IF_ERROR(1 != ret, pstEcPoint_1, "EC_POINT_set_affine_coordinates_GFp failed");
    // 重构后的点比较 主要判断重构点是否在椭圆曲线上
    if (1 == EC_POINT_is_on_curve(pstEcGroup_1, pstEcPoint_1, NULL)) 
    {
        fprintf(stdout, "====== 公钥点在椭圆曲线上! ======\n");
    }
    else
    {
        fprintf(stdout, "×××××× 公钥点不在椭圆曲线上! ××××××\n");
    }
    
    ret = 1;
cleanup:
    if (pstEcPoint_0)      EC_POINT_free(pstEcPoint_0);
    if (pstEcGroup_0)      EC_GROUP_free(pstEcGroup_0);
    if (pstEcPoint_1)      EC_POINT_free(pstEcPoint_1);
    if (pstEcGroup_1)      EC_GROUP_free(pstEcGroup_1);
    if (x)                 BN_free(x);
    if (y_0)               BN_free(y_0);
    if (y_1)               BN_free(y_1);
    
    return ret;
}
