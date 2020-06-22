#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

/**
	功能：将密文的哈希再通过密钥加密形成消息认证码
	1.构造hmac算法句柄
	2.hmac运算初始化
	3.执行hmac运算
	4.生成hmac
	5.释放hamc算法句柄
 */
 
 	// HASH_ALG_AUTO = 0,     /** 用于RSA签名验签函数内部检测算法 */
	// HASH_ALG_SHA384 = 1,  /**< SHA384摘要算法 */
	// HASH_ALG_SM3    = 2,  /**< SM3摘要算法 */
	// HASH_ALG_SHA256 = 3,   /**< SHA256摘要算法 */
	// HASH_ALG_MD5 = 4,		/**< MD5摘要算法 */
	// HASH_ALG_ECDSA_SM2 = 5, /**< SM2签名摘要算法，只用于SM2签名，验签作用，不适用HMAC等 */
	// HASH_ALG_SHA1 = 6,		/**< SHA1摘要算法 */
	// HASH_ALG_SHA512 = 7 	/**< SHA512摘要算法 */
 
static void test_hmac(void) {
	int halgs[] = { HASH_ALG_SHA384, HASH_ALG_SM3, HASH_ALG_SHA256, HASH_ALG_MD5, HASH_ALG_ECDSA_SM2, HASH_ALG_SHA1, HASH_ALG_SHA512};	//哈希算法种类
	const char* salgs[] = { "sha384", "sm3", "sha256", "md5", "sm2", "sha1", "sha512"};		
	int sizes[] = { 16, 64, 256, 1024, 4096 };		//密文长度
	HMAC_PCTX h;
	int n, m;
	unsigned char in[4096];			//密文内容
	unsigned char out[64];			//哈希结果（应该是16进制）
	const char key[16];				//加密哈希使用的密钥，也叫hashing-key

	for (n = 0; (unsigned int)n < sizeof(halgs)/sizeof(int); n ++) {
		for (m = 0; (unsigned int)m < sizeof(sizes)/sizeof(int); m ++) {
			printf("hmac(%d) name=[%s] buffersize=[%d] ", halgs[n], salgs[n], sizes[m]);
			int printflag = 1;
			benchmark(1);
			while (_bm.loop) {
				h = hmac_ctx_new(halgs[n]);
				if (printflag-- > 0)
					printf("hmacsize=[%d] ", hmac_size(h));
				hmac_init(h, (const unsigned char *)key, sizeof(key));
				hmac_update(h, in, sizes[m]);
				hmac_final(h, out);
				hmac_ctx_free(h);
				_bm.round ++;
			}
			benchmark(0);
			printf("round=[%d] time=[%fs] throughput=[%.2f]MB/s\n", _bm.round, _bm.e, _bm.round*sizes[m]/(_bm.e * 1000000));
		}
	}
}

int main(void) {
	test_hmac();
	return 0;
}
