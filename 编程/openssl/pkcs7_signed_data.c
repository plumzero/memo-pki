#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <assert.h>

/**
 * 加密消息语法（pkcs7），是各种消息存放的格式标准。这些消息包括：数据、签名数据、数字信封、签名数字信封、摘要数据和加密数据。
 *
 * 粗测 pkcs7 的长度，对 签名数据 测
 */
 
#define DEBUG

#ifdef DEBUG
#define test_printf(format, ...)	printf(format, ##__VA_ARGS__)
#else
#define test_printf(format, ...)
#endif

#define BUFSIZE		8092

int	main()
{
	PKCS7				*p7;
	int					i, j, len;
	unsigned char		*der,*p;
	FILE				*fp;
	X509				*x;
	BIO					*in;
	X509_ALGOR			*md;
	PKCS7_SIGNER_INFO	*si;

		
	// 构造 p7
	p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);
	p7->d.sign->cert = sk_X509_new_null();
	// 读取证书
	in = BIO_new_file("baiducom.crt", "r");
	x = PEM_read_bio_X509(in, NULL, NULL, NULL);
	// 提取信息，导入 p7
	sk_X509_push(p7->d.sign->cert, x);
	md = X509_ALGOR_new();
	md->algorithm = OBJ_nid2obj(NID_md5);
	sk_X509_ALGOR_push(p7->d.sign->md_algs, md);
	si = PKCS7_SIGNER_INFO_new();
	ASN1_INTEGER_set(si->version, 2);
	ASN1_INTEGER_set(si->issuer_and);
	
	p7=PKCS7_new();
	PKCS7_set_type(p7,NID_pkcs7_signed);
	p7->d.sign->cert=sk_X509_new_null();
	
	in=BIO_new_file("b64cert.cer","r");
	x=PEM_read_bio_X509(in,NULL,NULL,NULL);
	
	sk_X509_push(p7->d.sign->cert,x);
	md=X509_ALGOR_new();
	md->algorithm=OBJ_nid2obj(NID_md5);
	sk_X509_ALGOR_push(p7->d.sign->md_algs,md);
	si=PKCS7_SIGNER_INFO_new();
	ASN1_INTEGER_set(si->version,2);
	ASN1_INTEGER_set(si->issuer_and_serial->serial,333);
	sk_PKCS7_SIGNER_INFO_push(p7->d.sign->signer_info,si);
	len=i2d_PKCS7(p7,NULL);
	der=(unsigned char *)malloc(len);
	p=der;
	len=i2d_PKCS7(p7,&p);
	fp=fopen("p7_sign.cer","wb");
	fwrite(der,1,len,fp);
	fclose(fp);
	free(der);
	PKCS7_free(p7);
	return 0;
}

