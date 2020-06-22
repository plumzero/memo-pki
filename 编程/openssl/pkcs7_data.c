#include <string.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <assert.h>

/**
 * 加密消息语法（pkcs7），是各种消息存放的格式标准。这些消息包括：数据、签名数据、数字信封、签名数字信封、摘要数据和加密数据。
 *
 * 粗测 pkcs7 的长度，对 数据 测
 *
 * 配置 openssl 环境后编译，编译命令： gcc -g pkcs7_data.c -o pkcs7_data -I${头文件搜索路径} -L${库文件搜索路径} -lcrypto
 */
 
#define DEBUG

#ifdef DEBUG
#define test_printf(format, ...)	printf(format, ##__VA_ARGS__)
#else
#define test_printf(format, ...)
#endif

#define BUFSIZE		8192

int	main(int argc, char* argv[])
{
	PKCS7				*p7;
	int					i, j, slen, p7len, maxlen, cnt;
	unsigned char 		buf[BUFSIZE];
	unsigned char		*der, *p;
	FILE				*fp;
	
	if (argv[1]) maxlen = atoi(argv[1]);
	
	maxlen = argv[1] ? atoi(argv[1]) : BUFSIZE;
	assert(maxlen <= BUFSIZE);
	
	cnt = 0;
	
	for (i = 0; i < maxlen; i++) {
		der = NULL;
		p = NULL;
		p7 = NULL;
		memset(buf, 0, BUFSIZE);
		for (j = 0; j <= i; j++) {
			buf[j] = 0x65;
		}
		
		p7 = PKCS7_new();
		PKCS7_set_type(p7, NID_pkcs7_data);
		test_printf("data length = %4d\t", slen = i + 1);
		
		ASN1_OCTET_STRING_set(p7->d.data, (const unsigned char*)buf, slen);
		p7len = i2d_PKCS7(p7, NULL);
		der = (unsigned char*)malloc(p7len);
		p = der;
		assert(p7len == i2d_PKCS7(p7, (unsigned char **)&p));
		test_printf("pkcs7 length = %4d\t", p7len);
		if (p7) PKCS7_free(p7);
		if (der) free(der);
		// 求差
		test_printf("difference = %d\t", p7len - slen );
		if ((slen / 16 + 2) * 16 >= p7len)
		{
			cnt += 1;
			test_printf("\n");
		}
		else
			test_printf("failed\n");
	}
	if (cnt == maxlen)
		test_printf("success\n");
	else
		test_printf("failed(%d > %d)\n", maxlen, cnt);
	
	return 0;
}