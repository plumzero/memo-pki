
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
    gcc -g -O0 `pkg-config --cflags --libs libcrypto` gen_y.c -o gen_y -DKOAL_SSL_EXTENSION
    gcc -g -O0 `pkg-config --cflags --libs libcrypto` gen_y.c -o gen_y -DKOAL_SSL_EXTENSION -D_DEBUG  
  参考：
    OpenSSL密码库算法笔记——第5.4.13章 椭圆曲线点的压缩
    https://blog.csdn.net/samsho2/article/details/88104236
  说明：
    未带后缀 (_t, _s) 的为原始生成点，也是参照点；
    带 _t 的为将参照点压缩之后，再解压缩的点；
    带 _s 的为使用 EC_POINT_set_compressed_coordinates_GFp 将参照点处理之后，再还原的点；
  压缩及解压缩原理（猜测）：
    1. 已定椭圆曲线和一点的横坐标 x，作平行于 Y 轴直线 X = x，则与椭圆曲线交于两点。这两点均可作为公钥点，实际只
       取一点。所以可以在特定椭圆曲线上对公钥点压缩为一个横坐标 x。
    2. 解压缩与此相反。
    3. 从坐标系上看，横坐标对应的纵坐标有两个，+y 和 -y 。假设说 +y 的最右 bit 是 0，则对应的 -y 的最右 bit 一定
       是 1(补码...好像也不是补码原因，先不管)。反之亦然。
    4. 所以，解压缩时，如果想要真正的确定一个点，则必须知道 3 个条件：椭圆曲线，公钥点 x 坐标，y 的最右 bit 。
    5. 而在 coer 编码中，x-only 的情况下，会得到两个 y ，所以需要验证 2 次，有 1 次正确即成功。
    6. 不谈 coer 编码，国密标准中，会在 x 字节串前放置一个 PC 数 0x02 或 0x03 确定 y_bit 是 0 还是 1 (注意对应)。
       PC 数取值（压缩，未压缩，混合都是非无穷远点情形）：
         无穷远点形式:   0x00
         压缩表示形式:   0x02 或 0x03
         未压缩表示形式: 0x04
         混合表示形式:   0x06 或 0x07       
 */

/**
  接口：
     @param xOnlyBuf   _In_    公钥点 x 坐标字节串
     @param xOnlyLen   _In_    公钥点 x 坐标字节串长度(sm2 为 32 字节)
     @param yBuf_0     _Out_   公钥点 y 坐标字节串
     @param yLen_0     _Out_   公钥点 y 坐标字节串长度(sm2 为 32 字节)
     @param yBuf_1     _Out_   公钥点 y 坐标字节串
     @param yLen_1     _Out_   公钥点 y 坐标字节串长度(sm2 为 32 字节)
     @return 成功 0
     SGD_RV SDF_XOnly_Uncompressed(unsigned char xOnlyBuf[32], 
                                   size_t xOnlyLen, 
                                   unsigned char yBuf_0[32],
                                   size_t *yLen_0,
                                   unsigned char yBuf_1[32],
                                   size_t *yLen_1);
 */

int check()
{
    int ret = -1;
    // 生成组变量
    EC_GROUP *pstEcGroup = NULL;
    EC_KEY *pstEcKey = NULL;
    const EC_POINT *pstEcPoint = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    unsigned char szX[32] = { 0 };
    unsigned char szY[32] = { 0 };
    size_t i;
    unsigned char szXCompressedBuf[1024] = { 0 };
    size_t ulXCompressedLen;
    // 构造组变量
    EC_GROUP *pstEcGroup_t = NULL;
    EC_POINT *pstEcPoint_t = NULL;
    BIGNUM *x_t = NULL;
    BIGNUM *y_t = NULL;
    unsigned char szX_t[32] = { 0 };
    unsigned char szY_t[32] = { 0 };
    // 再构造组变量
    EC_GROUP *pstEcGroup_s = NULL;
    EC_POINT *pstEcPoint_s_0 = NULL;
    BIGNUM *x_s_0 = NULL;
    BIGNUM *y_s_0 = NULL;
    unsigned char szX_s_0[32] = { 0 };
    unsigned char szY_s_0[32] = { 0 };
    EC_POINT *pstEcPoint_s_1 = NULL;
    BIGNUM *x_s_1 = NULL;
    BIGNUM *y_s_1 = NULL;
    unsigned char szX_s_1[32] = { 0 };
    unsigned char szY_s_1[32] = { 0 };
    
    // 生成 sm2 密钥对
    pstEcGroup = EC_GROUP_new_by_curve_name(NID_CN_GM_ECC);
    STOP_IT_IF_ERROR(NULL == pstEcGroup, pstEcGroup, "EC_GROUP_new_by_curve_name failed");
    pstEcKey = EC_KEY_new();
    STOP_IT_IF_ERROR(NULL == pstEcKey, pstEcKey, "EC_KEY_new failed");
    ret = EC_KEY_set_group(pstEcKey, pstEcGroup);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_KEY_set_group failed");
    ret = EC_KEY_generate_key(pstEcKey);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_KEY_generate_key failed");
    
    // 获取公钥
    pstEcPoint = EC_KEY_get0_public_key(pstEcKey);
    STOP_IT_IF_ERROR(NULL == pstEcPoint, pstEcPoint, "EC_KEY_get0_public_key failed");
    x = BN_new();
    y = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(pstEcGroup, pstEcPoint, x, y, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_get_affine_coordinates_GFp failed");
    BN_bn2bin_ex(x, szX, 32);
    BN_bn2bin_ex(y, szY, 32);
#ifdef _DEBUG
    fprintf(stdout, "测试公钥点(x, y), 字节串表示:\n");
    fprintf(stdout, "公钥点 x:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szX[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
    fprintf(stdout, "公钥点 y:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szY[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
#endif
    // 重造椭圆曲线 进行简单的 点压缩&&解压缩 尝试
    pstEcGroup_t = EC_GROUP_new_by_curve_name(NID_CN_GM_ECC);
    STOP_IT_IF_ERROR(NULL == pstEcGroup_t, pstEcGroup_t, "EC_GROUP_new_by_curve_name failed");
    
    // 点压缩
    ulXCompressedLen = EC_POINT_point2oct(pstEcGroup_t, pstEcPoint, POINT_CONVERSION_COMPRESSED, 
                                            szXCompressedBuf, sizeof(szXCompressedBuf), NULL);
    STOP_IT_IF_ERROR(0 == ulXCompressedLen, "", "EC_POINT_point2oct failed");
#ifdef _DEBUG
    fprintf(stdout, "点压缩后(x, y*): %ld bytes\n", ulXCompressedLen);
    for (i = 0; i < ulXCompressedLen;) {
        fprintf(stdout, " %02X", szXCompressedBuf[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
    fprintf(stdout, "\n");
#endif  
    // 点解压缩
    pstEcPoint_t = EC_POINT_new(pstEcGroup_t);
    STOP_IT_IF_ERROR(NULL == pstEcPoint_t, pstEcPoint_t, "EC_POINT_new failed");
    ret = EC_POINT_oct2point(pstEcGroup_t, pstEcPoint_t, szXCompressedBuf, ulXCompressedLen, NULL);
    STOP_IT_IF_ERROR(1 != ret, pstEcPoint_t, "EC_POINT_oct2point failed");
    x_t = BN_new();
    y_t = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(pstEcGroup_t, pstEcPoint_t, x_t, y_t, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_get_affine_coordinates_GFp failed");
    BN_bn2bin_ex(x_t, szX_t, 32);
    BN_bn2bin_ex(y_t, szY_t, 32);
#ifdef _DEBUG
    fprintf(stdout, "点解压缩后, 还原公钥点 (x, y):\n");
    fprintf(stdout, "还原后的公钥点 x:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szX_t[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
    fprintf(stdout, "还原后的公钥点 y:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szY_t[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
#endif  
    // 点解压前后比较 包括 字节串比较，公钥点比较，还原点是否在椭圆曲线上
    if(0 != memcmp(szX, szX_t, 32) || 0 != memcmp(szY, szY_t, 32)) {
        fprintf(stdout, "====== 字节串点解压缩还原失败 ======\n");
        goto cleanup;
    }
    ret = EC_POINT_cmp(pstEcGroup_t, pstEcPoint, pstEcPoint_t, NULL);
    STOP_IT_IF_ERROR(0 != ret, "", "EC_POINT_cmp failed");
    ret = EC_POINT_is_on_curve(pstEcGroup_t, pstEcPoint_t, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_is_on_curve failed");
    
    // 再造椭圆曲线 以下是真正的测试
    pstEcGroup_s = EC_GROUP_new_by_curve_name(NID_CN_GM_ECC);
    STOP_IT_IF_ERROR(NULL == pstEcGroup_s, pstEcGroup_s, "EC_GROUP_new_by_curve_name failed");
    
    // 使用 EC_POINT_set_compressed_coordinates_GFp 函数
    pstEcPoint_s_0 = EC_POINT_new(pstEcGroup_s);
    STOP_IT_IF_ERROR(NULL == pstEcPoint_s_0, pstEcPoint_s_0, "EC_POINT_new failed");
    ret = EC_POINT_set_compressed_coordinates_GFp(pstEcGroup_s, pstEcPoint_s_0, x, 0, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_set_compressed_coordinates_GFp failed");
    x_s_0 = BN_new();
    y_s_0 = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(pstEcGroup_s, pstEcPoint_s_0, x_s_0, y_s_0, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_get_affine_coordinates_GFp failed");
    BN_bn2bin_ex(x_s_0, szX_s_0, 32);
    BN_bn2bin_ex(y_s_0, szY_s_0, 32);
    pstEcPoint_s_1 = EC_POINT_new(pstEcGroup_s);
    STOP_IT_IF_ERROR(NULL == pstEcPoint_s_1, pstEcPoint_s_1, "EC_POINT_new failed");
    ret = EC_POINT_set_compressed_coordinates_GFp(pstEcGroup_s, pstEcPoint_s_1, x, 1, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_set_compressed_coordinates_GFp failed");
    x_s_1 = BN_new();
    y_s_1 = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(pstEcGroup_s, pstEcPoint_s_1, x_s_1, y_s_1, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_get_affine_coordinates_GFp failed");
    BN_bn2bin_ex(x_s_1, szX_s_1, 32);
    BN_bn2bin_ex(y_s_1, szY_s_1, 32);
#ifdef _DEBUG
    fprintf(stdout, "点重构后(y_bit = 0), 公钥点 (x, y):\n");
    fprintf(stdout, "重构后的公钥点 x:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szX_s_0[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
    fprintf(stdout, "重构后的公钥点 y:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szY_s_0[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
    fprintf(stdout, "点重构后(y_bit = 1), 公钥点 (x, y):\n");
    fprintf(stdout, "重构后的公钥点 x:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szX_s_0[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
    fprintf(stdout, "重构后的公钥点 y:\n");
    for (i = 0; i < 32;) {
        fprintf(stdout, " %02X", szY_s_0[i]);
        if (0 == (++i % 16)) fprintf(stdout, "\n");
    }
#endif
    // 重构后的点比较 主要判断重构点是否在椭圆曲线上
    if ((0 == memcmp(szX, szX_s_0, 32) && 0 == memcmp(szY, szY_s_0, 32)) ||
        (0 == memcmp(szX, szX_s_1, 32) && 0 == memcmp(szY, szY_s_1, 32))) 
    {
        fprintf(stdout, "====== 字节串点解压缩还原成功... ======\n");
    }
    if (0 == EC_POINT_cmp(pstEcGroup_s, pstEcPoint, pstEcPoint_s_0, NULL) ||
        0 == EC_POINT_cmp(pstEcGroup_s, pstEcPoint, pstEcPoint_s_1, NULL))
    {
        fprintf(stdout, "====== 重构点与原来一致... ======\n");
    }
    if (1 == EC_POINT_is_on_curve(pstEcGroup_s, pstEcPoint_t, NULL)) 
    {
        fprintf(stdout, "====== 重构点在椭圆曲线上! ======\n");
    }
    
    ret = EC_POINT_is_on_curve(pstEcGroup_s, pstEcPoint_t, NULL);
    STOP_IT_IF_ERROR(1 != ret, "", "EC_POINT_is_on_curve failed");
    
    fprintf(stdout, "====== 测试成功 PC = %02X ======\n", szXCompressedBuf[0]);
    
    ret = 1;
cleanup:
    if (x_s_0)             BN_free(x_s_0);
    if (y_s_0)             BN_free(y_s_0);
    if (pstEcPoint_s_0)    EC_POINT_free(pstEcPoint_s_0);
    if (x_s_1)             BN_free(x_s_1);
    if (y_s_1)             BN_free(y_s_1);
    if (pstEcPoint_s_1)    EC_POINT_free(pstEcPoint_s_1);
    if (pstEcGroup_s)      EC_GROUP_free(pstEcGroup_s);
    if (x_t)               BN_free(x_t);
    if (y_t)               BN_free(y_t);
    if (pstEcPoint_t)      EC_POINT_free(pstEcPoint_t);
    if (pstEcGroup_t)      EC_GROUP_free(pstEcGroup_t);
    if (x)                 BN_free(x);
    if (y)                 BN_free(y);
    // if (pstEcPoint)        EC_POINT_free(pstEcPoint);
    if (pstEcGroup)        EC_GROUP_free(pstEcGroup);
    
    if (pstEcKey)          EC_KEY_free(pstEcKey);
    
    return ret;
}

int main() 
{   
    int count = 0;
    int i;
    
    for (i = 0; i < 100; i++)
        if (1 == check()) count++;
    
    if (100 == count)
        fprintf(stdout, "******************** 最终测试成功 ********************\n");
    
    return 0;
}