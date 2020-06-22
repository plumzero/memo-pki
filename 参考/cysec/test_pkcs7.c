#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

static void test_detached_without_attrs(void)
{
	const char* p[] = { "rsa", "sm2", "ecc"};
	int ret = 0;
	unsigned int n=0;
	
	for(n = 0; n < sizeof(p)/sizeof(char*); n ++){
		char path[256] = {0};
		unsigned char *plain = NULL, *p7 = NULL;
		size_t plen = 0, p7len = 0;
		X509CRT_PCTX x509 = NULL;

		//获取pkcs7格式的身份证书（sm2算法无法获取成功）
		/**
			提取步骤(以rsa加密为例)：
			openssl pkcs7 -inform der -in rsa.pkcs7.detached.without.attrs.der -outform pem -out pkcs7.raw.rsa.pem
			openssl pkcs7 -in pkcs7.raw.rsa.pem -print_certs -out pkcs7.rsa.cert.pem
			openssl x509 -in pkcs7.rsa.cert.pem -text -noout
		 */
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.detached.without.attrs.der", p[n]);		
		p7 = FILE_getcontent(path, &p7len);
		s_assert((p7 != NULL), "Failed to load pkcs7 (%s)", path);
		//获取明文数据
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.data.der", p[n]);		
		plain = FILE_getcontent(path, &plen);
		s_assert((plain != NULL), "Failed to load data (%s)", path);

		/** remove '\n' */
		if(plain[plen-1] == '\n'){
			plen -- ;
		}
		//验证pkcs7不带原文签名
		ret = cysec_pkcs7_detached_verify(plain, plen, p7, p7len, &x509);
		s_assert((ret == 0), "verify error... %08X\n", ret);

		if(x509){
			dumpcrt(x509);
			x509crt_free(x509);
		}

		SAFE_FREE(plain);
		SAFE_FREE(p7);		
	}	
}

static void test_detached_with_attrs(void)
{
	const char* p[] = { "rsa", "sm2", "ecc"};
	int ret = 0;
	unsigned int n=0;

	for(n = 0; n < sizeof(p)/sizeof(char*); n ++){
		char path[256] = {0};
		unsigned char *plain = NULL, *p7 = NULL;
		size_t plen = 0, p7len = 0;
		X509CRT_PCTX x509 = NULL;

		/**
			提取步骤(以rsa加密为例)：
			openssl pkcs7 -inform der -in rsa.pkcs7.detached.with.attrs.der -outform pem -out pkcs7.raw.rsa.attrs.pem
			openssl pkcs7 -in pkcs7.raw.rsa.attrs.pem -print_certs -out pkcs7.rsa.cert.attrs.pem
			openssl x509 -in pkcs7.rsa.cert.attrs.pem -text -noout
		 */
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.detached.with.attrs.der", p[n]);		
		p7 = FILE_getcontent(path, &p7len);
		s_assert((p7 != NULL), "Failed to load pkcs7 (%s)", path);

		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.data.der", p[n]);		
		plain = FILE_getcontent(path, &plen);
		s_assert((plain != NULL), "Failed to load data (%s)", path);

		/** remove '\n' */
		if(plain[plen-1] == '\n'){
			plen -- ;
		}

		ret = cysec_pkcs7_detached_verify(plain, plen, p7, p7len, &x509);
		s_assert((ret == 0), "verify error... %08X\n", ret);

		if(x509){
			dumpcrt(x509);
			x509crt_free(x509);
		}

		SAFE_FREE(plain);
		SAFE_FREE(p7);		
	}	
}

/**
	功能：验证pkcs7格式证书不带原文签名
	1.获取pkcs7证书内容
	2.获取原文数据（不是从pkcs7中获得）
	3.验证pkcs7不带原文签名
 */
static void test_detached(void)
{
	test_detached_with_attrs();
	test_detached_without_attrs();
}

static void test_attached_without_attrs(void)
{
	const char* p[] = { "rsa", "sm2", "ecc"};
	int ret = 0;
	unsigned int n=0;

	for(n = 0; n < sizeof(p)/sizeof(char*); n ++){
		char path[256] = {0};
		unsigned char *p7 = NULL;
		size_t p7len = 0;
		X509CRT_PCTX x509 = NULL;

		/**
			提取步骤(以rsa加密为例)：
			openssl pkcs7 -inform der -in rsa.pkcs7.attached.without.attrs.der -outform pem -out pkcs7.raw.rsa.attached.pem
			openssl pkcs7 -in pkcs7.raw.rsa.attached.pem -print_certs -out pkcs7.rsa.cert.attached.pem
			openssl x509 -in pkcs7.rsa.cert.attached.pem -text -noout
		 */
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.attached.without.attrs.der", p[n]);		
		p7 = FILE_getcontent(path, &p7len);
		s_assert((p7 != NULL), "Failed to load pkcs7 (%s)", path);
		//验证pkcs7带原文签名
		ret = cysec_pkcs7_attached_verify(p7, p7len, &x509);
		s_assert((ret == 0), "verify error... %08X\n", ret);

		if(x509){
			dumpcrt(x509);
			x509crt_free(x509);
		}

		SAFE_FREE(p7);		
	}	
}

static void test_attached_with_attrs(void)
{
	const char* p[] = { "rsa", "sm2", "ecc"};
	int ret = 0;
	unsigned int n=0;

	for(n = 0; n < sizeof(p)/sizeof(char*); n ++){
		char path[256] = {0};
		unsigned char *p7 = NULL;
		size_t p7len = 0;
		X509CRT_PCTX x509 = NULL;

		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.attached.with.attrs.der", p[n]);		
		p7 = FILE_getcontent(path, &p7len);
		s_assert((p7 != NULL), "Failed to load pkcs7 (%s)", path);

		ret = cysec_pkcs7_attached_verify(p7, p7len, &x509);
		s_assert((ret == 0), "verify error... %08X\n", ret);

		if(x509){
			dumpcrt(x509);
			x509crt_free(x509);
		}

		SAFE_FREE(p7);		
	}	
}

/**
	功能：验证pkcs7格式证书带原文签名
	1.获取pkcs7证书内容
	2.验证pkcs7不带原文签名
 */
static void test_attached(void )
{
	test_attached_with_attrs();
	test_attached_without_attrs();
}

/**
	功能：Alice将自己的身份证书使用数字签名后发送给Bob。发生于通信双方之间，Alice向Bob发送数据，Alice为了保证自己发送的数据具有保密性，完整性和真实性，
	Alice会对数据进行数字签名在这里与其称为数字签名，称为消息摘要更好些。数字签名和消息摘要只是不同场景下的同一种应用
	
	在下面的测试中，Alice是signer，Bob是recipient
	
	暂时这样认为：
	如果对明（密）文哈希，之后使用私钥加密是数字签名
	如果对明（密）文哈希，是消息摘要
 */
static void test_seal(void)
{
	const char *p[] = { "rsa", "sm2", "ecc" };
	int ret = 0;
	unsigned int n=0;

	for( n = 0; n < sizeof(p)/sizeof(char *); n ++ )
	{
		char path[256] = {0};
		X509CRT_PCTX recip_x509 = NULL;
		PKEY_PCTX signer_pkey = NULL;
		X509CRT_PCTX signer_x509 = NULL;
		unsigned char buf[4] = "123";
		size_t blen = sizeof(buf);
		unsigned char *seal = NULL;
		size_t slen = 0;
		//获取Bob的身份证书
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.recipient.crt.pem", p[n]);
		recip_x509 = FILE_getcrt(path);
		s_assert((recip_x509 != NULL), "load recipient certificate %s\n error", path);
		if(!recip_x509)
			goto freebuffer;
		//获取Alice私钥
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.signer.pvk.pem", p[n]);
		signer_pkey = FILE_getpvk(path);
		s_assert((signer_pkey != NULL), "load signer prviatekey %s\n error", path);
		if(!signer_pkey)
			goto freebuffer;
		//获取Alice身份证书
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.signer.crt.pem", p[n]);
		signer_x509 = FILE_getcrt(path);
		s_assert((signer_x509 != NULL), "load signer certificate %s\n error", path);
		if(!signer_x509)
			goto freebuffer;
		/**
			(Alice与Bob作为通信双方身份平等)
			1.Alice将明文（buf）使用Bob的公钥加密，公钥存在于Bob的身份证书中（recip_x509）
			2.Alice将密文生成哈希（Bob将自己支持的哈希算法存放于证书recip_x509中，Alice根据Bob提供的哈希方法进行哈希）
			3.Alice使用自己的私钥加密哈希形成消息摘要
			4.Alice将自己的身份证书+密文+消息摘要三者一起，形成pkcs7
			5.Alice将封装好的pkcs7形式数据发送给Bob
			
			pkcs7作为一种加密消息的语法标准，不仅可以用作数据加密，也可用于数字签名
			
			(Alice作为Bob的发证者存在)  。。。延伸
			假如Alice是一个CA，要给Bob创建一张身份证书，流程如下：
			1.Bob将自己的身份信息使用自己的私钥加密后传给Alice
			2.Alice确认Bob身份信息，将密文哈希
			3.Alice补充进去自己的元数据（愿意的话），之后编码哈希和元数据（一般使用base64）
			4.Alice使用自己的私钥加密编码，形成数字签名
			5.Alice将创建好的带有数字签名的证书发送给Bob
		 */
		 /**
			提取步骤(以rsa加密为例)：
			openssl pkcs7 -in rsa.pkcs7.seal.pem -print_certs -out pkcs7.rsa.cert.pem
			openssl x509 -in pkcs7.rsa.cert.pem -text -noout
		 */
		ret = cysec_pkcs7_SignedAndEnveloped_seal(buf, blen, recip_x509, signer_pkey, signer_x509, &seal, &slen, PEM);
		if(ret)
			goto freebuffer;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.seal.pem", p[n]);
		ret = FILE_putcontent(seal,slen, path);
		if(ret)
			goto freebuffer;

		SAFE_FREE(seal);
		ret = cysec_pkcs7_SignedAndEnveloped_seal(buf, blen, recip_x509, signer_pkey, signer_x509, &seal, &slen, DER);
		if(ret)
			goto freebuffer;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.seal.der", p[n]);
		ret = FILE_putcontent(seal, slen, path);
		if(ret)
			goto freebuffer;

		SAFE_FREE(seal);
	freebuffer:
		SAFE_FREE(seal);
		if(recip_x509)
			cysec_x509crt_free(recip_x509);
		if(signer_x509)
			cysec_x509crt_free(signer_x509);
		if(signer_pkey)
			cysec_pkey_free(signer_pkey);
	}
}

static void test_open(void)
{
	const char *p[] = { "rsa", "sm2", "ecc" };
	int ret = 0;
	unsigned int n=0;

	for( n = 0; n < sizeof(p)/sizeof(char *); n ++ )
	{
		char path[256] = {0};
		X509CRT_PCTX recip_x509 = NULL;
		PKEY_PCTX recip_pkey = NULL;
		unsigned char *seal_pem = NULL, *seal_der = NULL;
		size_t seal_der_len = 0;
		unsigned char *plain_pem = NULL, *plain_der = NULL;
		size_t  plain_der_len = 0;
		CERTMGR_PCTX cm = NULL;
		X509CRT_PCTX signer_x509 = NULL,cacert = NULL;
		//获取Bob的身份证书
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.recipient.crt.pem", p[n]);
		recip_x509 = FILE_getcrt(path);
		s_assert((recip_x509 != NULL), "load recipient certificate %s\n error", path);
		if(!recip_x509)
			goto freebuffer;
		//获取Bob的私钥
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.recipient.pvk.pem", p[n]);
		recip_pkey = FILE_getpvk(path);
		s_assert((recip_pkey != NULL), "load recipient prviatekey %s\n error", path);
		if(!recip_pkey)
			goto freebuffer;
		//获取二级ca的身份证书(Alice和Bob的身份证书都由二级ca签发)
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.cacrt.pem", p[n]);
		cacert = FILE_getcrt(path);
		s_assert((cacert != NULL), "load signer certificate %s\n error", path);
		if(!cacert)
			goto freebuffer;			

		cm = cysec_certmgr_new();
		if(!cm)
			goto freebuffer;
		//二级CA证书添加到证书管理器中
		ret = cysec_certmgr_add_ca(cm, cacert);
		if(ret)
			goto freebuffer;

		/**
			提取步骤(以rsa加密为例)：
			openssl pkcs7 -inform der -in rsa.pkcs7.seal.der -print_certs -out pkcs7.rsa.seal.pem
			openssl x509 -in pkcs7.rsa.seal.pem -text -noout
		 */
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.seal.der", p[n]);		//rsa.pkcs7.seal.der包含Alice的身份证书
		seal_der = FILE_getcontent(path, &seal_der_len);
		if(!seal_der)
			goto freebuffer;
		/**
			1.Bob从pkcs7中获取Alice的身份证书(signer_x509)
			2.Bob使用Alice的公钥解密消息摘要，还原哈希
			3.Bob重新哈希密文，生成新哈希，与还原的哈希比对，2，3两步共同确认消息完整性和真实性
			4.Bob使用自己的私钥还原密文，确认消息的保密性
		 */
		ret = cysec_pkcs7_SignedAndEnveloped_open(seal_der, seal_der_len, recip_x509, recip_pkey, &plain_der, &plain_der_len, &signer_x509);
		s_assert( (ret == 0),"open enveloped error %08x\n",ret);
		if(ret)
			goto freebuffer;

		if(!signer_x509){
			printf("can't found signer certificate.\n");
			goto freebuffer;
		}
		/**
			上面其实已经验证了Alice的身份，这里证书管理器应该只是验证Alice的证书是否有效（黑名单，证书链）
		 */
		ret = cysec_certmgr_verify(cm, signer_x509);
		s_assert(( ret == 0), "verify Chain error %08x\n",ret);
		if(ret)
			goto freebuffer;

		printf("plain_der (%s)\n", plain_der);
		SAFE_FREE(plain_der);

	freebuffer:
		SAFE_FREE(seal_pem);
		SAFE_FREE(seal_der);
		SAFE_FREE(plain_pem);
		SAFE_FREE(plain_der);
		if(cacert)
			cysec_x509crt_free(cacert);

		if(recip_x509)
			cysec_x509crt_free(recip_x509);

		if(signer_x509)
			cysec_x509crt_free(signer_x509);

		if(recip_pkey)
			cysec_pkey_free(recip_pkey);

		if(cm)
			cysec_certmgr_free(cm);		
	}
}

static void test_pkcs7_sign_ex(const char *save_file_path, int flags)
{
	const char *p[] = { "rsa", "sm2", "ecc" };
	int ret = 0;
	unsigned int n=0;

	for( n = 0; n < sizeof(p)/sizeof(char *); n ++ )
	{
		char path[256] = {0};
		PKEY_PCTX signer_pkey = NULL;
		X509CRT_PCTX signer_x509 = NULL;
		unsigned char buf[4] = "123";
		size_t blen = sizeof(buf);
		unsigned char *seal = NULL;
		size_t slen = 0;
		//获取Alice私钥
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.signer.pvk.pem", p[n]);
		signer_pkey = FILE_getpvk(path);
		s_assert((signer_pkey != NULL), "load signer prviatekey %s\n error", path);
		if(!signer_pkey)
			goto freebuffer;
		//获取Alice身份证书
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.signer.crt.pem", p[n]);
		signer_x509 = FILE_getcrt(path);
		s_assert((signer_x509 != NULL), "load signer certificate %s\n error", path);
		if(!signer_x509)
			goto freebuffer;			
		/**
			pkcs7作为一种加密消息的语法标准，不仅可以用作数据加密，也可用于数字签名
			
			(Alice作为Bob的发证者存在)
			假如Alice是一个CA，要给Bob创建一张身份证书，流程如下：
			1.Bob将自己的身份信息使用自己的私钥加密后传给Alice
			2.Alice确认Bob身份信息，将密文哈希
			3.Alice补充进去自己的元数据（愿意的话），之后编码哈希和元数据（一般使用base64）
			4.Alice使用自己的私钥加密编码，形成数字签名
			5.Alice将创建好的带有数字签名的证书发送给Bob
			
			本例并没有对身份证书进行数字签名，只是对数据进行数字签名，称为消息摘要更好些
			1.Alice使用自己的私钥对数据（buf）进行加密形成伪消息摘要（严格意义上来说，这里并不是消息摘要）
			2.Alice将自己的身份证书和伪消息摘要一起，封装成pkcs7(seal)
		 */
		ret = cysec_pkcs7_sign(buf, blen, signer_pkey, signer_x509, flags, &seal, &slen, PEM);
		if(ret)
			goto freebuffer;
		
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.sign.%s.pem", p[n], save_file_path);
		ret = FILE_putcontent(seal,slen, path);
		if(ret)
			goto freebuffer;
		
		SAFE_FREE(seal);
		ret = cysec_pkcs7_sign(buf, blen, signer_pkey, signer_x509, flags, &seal, &slen, DER);
		if(ret)
			goto freebuffer;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.sign.%s.der", p[n], save_file_path);
		ret = FILE_putcontent(seal, slen, path);
		if(ret)
			goto freebuffer;

		SAFE_FREE(seal);
	freebuffer:
		SAFE_FREE(seal);
		if(signer_x509)
			cysec_x509crt_free(signer_x509);
		if(signer_pkey)
			cysec_pkey_free(signer_pkey);
	}
}

static void test_pkcs7_sign_verify_ex(const char *save_file_path, int flags)
{
	const char *p[] = { "rsa", "sm2", "ecc" };
	int ret = 0;
	unsigned int n=0;

	for( n = 0; n < sizeof(p)/sizeof(char *); n ++ )
	{
		char path[256] = {0};
		X509CRT_PCTX cacert = NULL;
		unsigned char *seal_der = NULL;
		size_t seal_der_len = 0;
		CERTMGR_PCTX cm = NULL;
		X509CRT_PCTX signer_x509 = NULL;
		unsigned char buf[4] = "123";
		size_t blen = sizeof(buf);
		
		//获取二级ca证书
		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.cacrt.pem", p[n]);
		cacert = FILE_getcrt(path);
		s_assert((cacert != NULL), "load signer certificate %s\n error", path);
		if(!cacert)
			goto freebuffer;			
		//构造证书管理器
		cm = cysec_certmgr_new();
		if(!cm)
			goto freebuffer;
		//二级ca证书加入证书管理器中
		ret = cysec_certmgr_add_ca(cm, cacert);
		if(ret)
			goto freebuffer;
		//获取pkcs7格式数据
		memset(path, 0, sizeof(path));
		// snprintf(path, sizeof(path), "./kpool/%s.pkcs7.sign.der", p[n]);
		snprintf(path, sizeof(path), "./kpool/%s.pkcs7.sign.%s.pem", p[n], save_file_path);
		seal_der = FILE_getcontent(path, &seal_der_len);
		if(!seal_der)
			goto freebuffer;
		//对pkcs7格式数据进行验证，并返回签发者（Alice = signer_x509）身份证书
		if (flags & CYSEC_PKCS7_FLAG_DETACHED )
		{
			ret = cysec_pkcs7_detached_verify(buf, blen, seal_der, seal_der_len, &signer_x509);
		} else {
			ret = cysec_pkcs7_attached_verify(seal_der, seal_der_len, &signer_x509);
		}
		s_assert( (ret == 0),"open enveloped error %08x\n",ret);
		if(ret)
			goto freebuffer;

		if(!signer_x509){
			printf("can't found signer certificate.\n");
			goto freebuffer;
		}
		//验证Alice是否黑名单，或证书链是否完整等等
		ret = cysec_certmgr_verify(cm, signer_x509);
		s_assert(( ret == 0), "verify Chain error %08x\n",ret);
		if(ret)
			goto freebuffer;

		printf("plain_der (%s)\n", buf);

	freebuffer:
		SAFE_FREE(seal_der);
		if(cacert)
			cysec_x509crt_free(cacert);

		if(signer_x509)
			cysec_x509crt_free(signer_x509);

		if(cm)
			cysec_certmgr_free(cm);		
	}
}

static void test_pkcs7_sign_detached_without_attrs(void)
{
	int flags = CYSEC_PKCS7_FLAG_DETACHED | CYSEC_PKCS7_FLAG_WITHOUT_ATTRIBUTES;
	const char *path = "detached_without_attrs";

	test_pkcs7_sign_ex(path, flags);
	test_pkcs7_sign_verify_ex(path, flags);
}

static void test_pkcs7_sign_detached_with_attrs(void)
{
	int flags = CYSEC_PKCS7_FLAG_DETACHED | CYSEC_PKCS7_FLAG_WITH_ATTRIBUTES;
	const char *path = "detached_with_attrs";

	test_pkcs7_sign_ex(path, flags);
	test_pkcs7_sign_verify_ex(path, flags);
}

static void test_pkcs7_sign_attached_without_attrs(void)
{
	int flags = CYSEC_PKCS7_FLAG_ATTACHED | CYSEC_PKCS7_FLAG_WITHOUT_ATTRIBUTES;
	const char *path = "attached_without_attrs";

	test_pkcs7_sign_ex(path, flags);
	test_pkcs7_sign_verify_ex(path, flags);
}

static void test_pkcs7_sign_attached_with_attrs(void)
{
	int flags = CYSEC_PKCS7_FLAG_ATTACHED | CYSEC_PKCS7_FLAG_WITH_ATTRIBUTES;
	const char *path = "attached_with_attrs";

	test_pkcs7_sign_ex(path, flags);
	test_pkcs7_sign_verify_ex(path, flags);
}

static void test_pkcs7_sign(void)
{
	test_pkcs7_sign_detached_without_attrs();
	test_pkcs7_sign_detached_with_attrs();
	test_pkcs7_sign_attached_without_attrs();
	test_pkcs7_sign_attached_with_attrs();
}

static void test(void)
{
	test_detached();
	test_attached();
	test_seal();
	test_open();
	test_pkcs7_sign();
}

int main(void)
{
	test();
	exit(0);
}