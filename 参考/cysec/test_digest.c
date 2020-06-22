#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

/**
	功能：哈希密文，数字签名
	1.构造算法句柄
	2.哈希运算初始化
	3.执行哈希运算
	4.获取哈希
	5.释放算法句柄
 */

		// HASH_ALG_AUTO = 0,     /** 用于RSA签名验签函数内部检测算法 */
		// HASH_ALG_SHA384 = 1,  /**< SHA384摘要算法 */
		// HASH_ALG_SM3    = 2,  /**< SM3摘要算法 */
		// HASH_ALG_SHA256 = 3,   /**< SHA256摘要算法 */
		// HASH_ALG_MD5 = 4,		/**< MD5摘要算法 */
		// HASH_ALG_ECDSA_SM2 = 5, /**< SM2签名摘要算法，只用于SM2签名，验签作用，不适用HMAC等 */
		// HASH_ALG_SHA1 = 6,		/**< SHA1摘要算法 */
		// HASH_ALG_SHA512 = 7 	/**< SHA512摘要算法 */
 
static void test_digest_benchmark(void) {
	int halgs[] = { HASH_ALG_SHA384, HASH_ALG_SM3, HASH_ALG_SHA256, HASH_ALG_MD5, HASH_ALG_ECDSA_SM2, HASH_ALG_SHA1, HASH_ALG_SHA512 };		//哈希算法种类
	const char* salgs[] = { "sha384", "sm3", "sha256", "md5", "sm2", "sha1", "sha512" };
	int sizes[] = { 16, 64, 256, 1024, 4096 };		//密文长度
	DIGEST_PCTX h;
	int n, m;
	unsigned char in[4096];			//密文内容
	unsigned char out[64];			//哈希结果（应该是16进制）
	
	for (n = 0; (unsigned int)n < sizeof(halgs)/sizeof(int); n ++) {
		for (m = 0; (unsigned int)m < sizeof(sizes)/sizeof(int); m ++) {
			printf("digest(%d) name=[%s] buffersize=[%d] mdsize=[%d] ", halgs[n], salgs[n], sizes[m], cysec_digest_size(halgs[n]));
			benchmark(1);
			while (_bm.loop) {
				h = digest_ctx_new(halgs[n]);
				digest_init(h, NULL);
				digest_update(h, in, sizes[m]);
				digest_final(h, out);
				digest_ctx_free(h);
				_bm.round ++;
			}
			benchmark(0);
			printf("round=[%d] time=[%fs] throughput=[%.2f]MB/s\n", _bm.round, _bm.e, _bm.round*sizes[m]/(_bm.e * 1000000));
		}
	}
}

static const unsigned char sm3_test_buf[2][64] =
{
    { "abc" },
    { "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" },
};

static const int sm3_test_buflen[2] =
{
    3, 64
};

static const unsigned char sm3_test_sum[2][32] =
{
    /*
     * SM3 test vectors
     */
    { 0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
      0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
      0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
      0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0 },
    { 0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
      0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
      0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
      0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32 },
};

/*
 * Checkup routine
 */
 /**
	sm3算法，知道就好
  */
static int cysec_sm3_self_test( int verbose )
{
    int i, j, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sm3sum[32];
    DIGEST_PCTX h;


    for( i = 0; i < 2; i++ )
    {
        j = i % 3;

        if( verbose != 0 )
            printf( "  SM3 test #%d: ", j + 1 );

	    h = cysec_digest_ctx_new(HASH_ALG_SM3);
	    if(!h) {
	    	printf("sm3 test failed.\n");
	    	return CYSEC_E_MEMORY_E;
	    }

	    digest_init(h, NULL);

        if( j == 2 )
        {
            memset( buf, 'a', 1000 );
            buflen = 1000;
            for( j = 0; j < 1000; j++ )
                digest_update( h, buf, buflen );
        }
        else
            digest_update( h, sm3_test_buf[j],
                                 sm3_test_buflen[j] );

        digest_final( h, sm3sum );
        digest_ctx_free(h);
        if( memcmp( sm3sum, sm3_test_sum[i], 32 ) != 0 )
        {
            if( verbose != 0 )
                printf( "failed\n" );

            hexdump(sm3sum, 32);
            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            printf( "passed\n" );
    }

    if( verbose != 0 )
        printf( "\n" );

exit:

    return( ret );
}


static void test_digest_verify(void)
{
	cysec_sm3_self_test(1);
}

int main(void) {
	test_digest_verify();
	test_digest_benchmark();
	return 0;
}
