#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

/**
	功能:ecb加密模式benchmark测试
		对两种对称加密算法aes256 sm4进行分块加密，测试指定时间内（3s）内每种加密算法的加密轮数
	ecb模式简介：事先设置数据填充项，之后将数据分块，每块长度与加密密钥等长，最后对每块单独加密
 */
static void test_cipher_ecb_benchmark(void) {
	printf("******对ecb模式进行benchmark测试******\n");
	int calgs[] = { CIPHER_ALG_AES256_ECB, CIPHER_ALG_SM4_ECB };
	const char* salgs[] = { "aes256", "sm4" };
	int sizes[] = { 64, 256, 1024, 4096 };		//明文长度，如果明文长度低于某个值，则以某固定填充至所指定长度
	CIPHER_PCTX h;
	int i, n, m;
	unsigned char key[32] = {0};				//每块长度32位
	unsigned char in[4096] = {0};
	unsigned char out[4096 + 32] = {0};
	unsigned char tmp[4096 + 32] = {0} ;
	size_t tlen, olen;
	
	for (n = 0; (unsigned int)n < sizeof(calgs)/sizeof(int); n ++) {
		for (m = 0; (unsigned int)m < sizeof(sizes)/sizeof(int); m ++) {
			printf("cipher(%d) name=(%s) mode(ecb) blocksize=%d, keysize=%d, buffersize=[%d] ", 
			       calgs[n], salgs[n], 
						 cipher_block_size(calgs[n]), 		//block size 与 key size 相同
						 cipher_key_size(calgs[n]), 
						 sizes[m]);
			benchmark(1);
			while (_bm.loop) {
				h = cipher_ctx_new(calgs[n]);
				cipher_set_key(h, key, cysec_cipher_key_size(calgs[n]), 1);
				cysec_cipher_init(h);
				/**
					以m=1为例，假设明文长度 240
					则会事先将原明文填充至256个长度
					256/32 = 8，将明文分成8块，对新明文按顺序加密，每次加密32个字符，但加密后的密文长度未必是32个字符
					
					可能还有理解不对的地方
				 */
				for( i = 0; i<sizes[m]/cipher_block_size(calgs[n]); i++ ){
					cysec_cipher_update(h, in + i*cipher_block_size(calgs[n]), cipher_block_size(calgs[n]), out, &tlen);
					olen +=tlen;
				}
				cysec_cipher_final(h, out+olen, &olen);
				cipher_ctx_free(h);
				//hexdump(out, sizes[m]);
				_bm.round ++;
			}
			benchmark(0);
			printf("round=[%d] time=[%fs] throughput=[%.2f]MB/s\n", _bm.round, _bm.e, _bm.round*sizes[m]/(_bm.e * 1000000));
		}
	}
}

/**
	功能:cbc加密模式benchmark测试
		1.对aes256和sm4两种对称加密算法，使用cbc模式进行加密解密测试
		2.对两种对称加密算法aes256 sm4进行分块加密，测试指定时间内（3s）内每种加密算法的加密轮数
	cbc模式简介：
		在ECB模式基础上引入初始化向量(IV)，即使输入数据相同，加密结果也不同。
		加密开始前生成一个与每块长度相同的IV。第一块数据与IV进行XOR运算，使用上次的运行结果作为新的IV与下面的数据进行XOR运算，依次类推。
 */
static void test_cipher_cbc_benchmark(void ) {
	printf("******执行cbc模式的对称加密解密过程，并进行benchmark测试******\n");
	int calgs[] = { CIPHER_ALG_AES256_CBC, CIPHER_ALG_SM4_CBC };
	const char* salgs[] = { "aes256", "sm4" };
	int sizes[] = { 16, 64, 256, 1024, 4096 };
	CIPHER_PCTX h;
	int n, m;
	unsigned char key[32] = {0};
	unsigned char iv[32] = {0};
	unsigned char in[4096] = {0};
	unsigned char out[4096 + 32] = {0};
	unsigned char tmp[4096 + 32] = {0} ;
	size_t olen;
	
	for (n = 0; (unsigned int)n < sizeof(calgs)/sizeof(int); n ++) {
		for (m = 0; (unsigned int)m < sizeof(sizes)/sizeof(int); m ++) {
			printf("cipher(%d) name=(%s) mode(cbc) blocksize=%d, keysize=%d, ivsize=%d buffersize=[%d] ", 
			       calgs[n], salgs[n], 
						 cipher_block_size(calgs[n]), 
						 cipher_key_size(calgs[n]), 
						 cipher_iv_size(calgs[n]),
						 sizes[m]);

			h = cipher_ctx_new(calgs[n]);
			cipher_set_key(h, key, cysec_cipher_key_size(calgs[n]), 1);
			cysec_cipher_set_iv(h, iv, cysec_cipher_iv_size(calgs[n]));
			olen = sizeof(out);
			cipher_cbc(h, out, &olen, in, sizes[m]);
			cipher_ctx_free(h);
			//hexdump(key, sizeof(key));
			//hexdump(iv, sizeof(iv));
			//hexdump(in, sizes[m]);
			//hexdump(out, sizes[m]);

			h = cipher_ctx_new(calgs[n]);
			cipher_set_key(h, key, cysec_cipher_key_size(calgs[n]), 0);
			cysec_cipher_set_iv(h, iv, cysec_cipher_iv_size(calgs[n]));
			cipher_cbc(h, tmp, &olen, out, olen);
			cipher_ctx_free(h);
			//hexdump(key, sizeof(key));
			//hexdump(iv, sizeof(iv));
			//hexdump(out, sizes[m]);
			//hexdump(tmp, sizes[m]);

			if (memcmp(in, tmp, sizes[m])) {
				//hexdump(in, sizes[m]);
				//hexdump(tmp, sizes[m]);
				printf("cipher enc/dec test failed!\n");
				exit(-1);
			}

			benchmark(1);
			while (_bm.loop) {
				h = cipher_ctx_new(calgs[n]);
				cipher_set_key(h, key, cysec_cipher_key_size(calgs[n]), 1);
				cysec_cipher_set_iv(h, iv, cysec_cipher_iv_size(calgs[n]));
				olen = sizeof(out);
				cipher_cbc(h, out, &olen, in, sizes[m]);
				cipher_ctx_free(h);
				//hexdump(out, sizes[m]);
				_bm.round ++;
			}
			benchmark(0);
			printf("round=[%d] time=[%fs] throughput=[%.2f]MB/s\n", _bm.round, _bm.e, _bm.round*sizes[m]/(_bm.e * 1000000));
		}
	}
}
/**
	cbc模式使用sm4对称加密算法对数据进行分组加密解密测试
 */
void test_cipher_cbc_encdec( void )
{
	printf("******使用cbc模式对明文进行加密与解密******\n");
	const char *message = "-----BEGIN CERTIFICATE-----\n\
	MIICQTCCAaqgAwIBAgINALyhOvNi4bUyYIbA5TANBgkqhkiG9w0BAQsFADAvMQsw\n\
	CQYDVQQGEwJDTjEPMA0GA1UEChMGY2FzaXRlMQ8wDQYDVQQDEwZjYXNpdGUwIhgP\n\
	MjAxNjEyMTkxNjAwMDBaGA8yMDM3MTIxNzE2MDAwMFowLzELMAkGA1UEBhMCQ04x\n\
	DzANBgNVBAoTBmNhc2l0ZTEPMA0GA1UEAxMGY2FzaXRlMIGfMA0GCSqGSIb3DQEB\n\
	AQUAA4GNADCBiQKBgQDu/ow85U0ZvD8x4JN29wN20KtDE3/EbsUyxXzTq4IyBDql\n\
	mftxmA7GVdtqZSIFxO/EXb7ubBJUU5F6SUKpbjcEJgqKH5AxCs72dPiv4w4i6/D+\n\
	FQ4tARDlDxZ9GTFL69YyjAOluSsQ0i/F51YUNI7rcZFfr1+0xGupo/lCx4v6QQID\n\
	AQABo10wWzAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBTxP6PlaJPFU/sF+uErM4tj\n\
	NegdUjAfBgNVHSMEGDAWgBTxP6PlaJPFU/sF+uErM4tjNegdUjALBgNVHQ8EBAMC\n\
	AYYwDQYJKoZIhvcNAQELBQADgYEAHq+u+k9s8D/DFM36aXqeIgQBnrESB8aj+qFt\n\
	jVYLw4QpyVn93duwv3KOFybsP870UjQWRp5uBJSulu3DSSNalYFNNrI0IAyByfWU\n\
	jdD5pvtMzVCkEtAQ33fRvxRmNEYLIU3Tb1Q0tDP20o22J4+jcz5zSun7RoaCCdpP\n\
	DX4Zm48=\n\
	-----END CERTIFICATE-----";
	size_t mlen = 0, len = 0, tmplen = 0, tmplen2 = 0;

	const unsigned char key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
	unsigned char iv[16] = {0};
	unsigned char out[4096] = {0};
	unsigned char plain[4096] = {0};
	size_t olen = 4096;
	CIPHER_PCTX h;
	const unsigned char *p = NULL;
	unsigned char *pout = NULL;
	size_t split_len = 112;		//分块时每块的长度

	h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
	if(!h){
		printf("out of memory\n");
		return ;
	}

	p = (unsigned char *)message;
	mlen = strlen(message);
	len = mlen;
	pout = out;
	
	cipher_set_key(h, key, sizeof(key), 1);
	cysec_cipher_set_iv(h, iv, sizeof(iv));
	cysec_cipher_init(h);
	while(len)		//明文长度
	{
		tmplen = olen;
		if( len >= split_len) {
			cysec_cipher_update(h, p, split_len, pout, &tmplen);
			p += split_len;
			pout += tmplen;
			olen -= tmplen;
			len -= split_len;
			tmplen2 += tmplen;
		} else {
			cysec_cipher_update(h, p, len, pout, &tmplen);
			p += len;
			tmplen2 += tmplen;
			len -= len;
			pout += tmplen;
			olen -= tmplen;
		}
	}

	cysec_cipher_final(h, pout, &tmplen);
	tmplen2 += tmplen;			///为什么要进行一个加项？？？
	cipher_ctx_free(h);

	h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
	if(!h) {
		printf("out of memory\n");
		return ;
	}

	cipher_set_key(h, key, cysec_cipher_key_size(CIPHER_ALG_SM4_CBC), 0);
	cysec_cipher_set_iv(h, iv, cysec_cipher_iv_size(CIPHER_ALG_SM4_CBC));
	tmplen = sizeof(plain);
	cipher_cbc(h, plain, &tmplen, out, tmplen2);
	cipher_ctx_free(h);

	if ( memcmp(plain, message, tmplen ) != 0 || mlen != tmplen) {
		printf("test cbc failed.\n");
	} else
		printf("test cbc success.\n");

}

/**
	事先设置数据填充项，之后cbc模式下使用sm4对称加密算法对数据进行分组加密解密测试
 */
void test_cipher_padding_mode(void)
{
	printf("******使用cbc填充模式对明文进行加密与解密******\n");
	const char *message = "-----BEGIN CERTIFICATE-----\n\
	MIICQTCCAaqgAwIBAgINALyhOvNi4bUyYIbA5TANBgkqhkiG9w0BAQsFADAvMQsw\n\
	CQYDVQQGEwJDTjEPMA0GA1UEChMGY2FzaXRlMQ8wDQYDVQQDEwZjYXNpdGUwIhgP\n\
	MjAxNjEyMTkxNjAwMDBaGA8yMDM3MTIxNzE2MDAwMFowLzELMAkGA1UEBhMCQ04x\n\
	DzANBgNVBAoTBmNhc2l0ZTEPMA0GA1UEAxMGY2FzaXRlMIGfMA0GCSqGSIb3DQEB\n\
	AQUAA4GNADCBiQKBgQDu/ow85U0ZvD8x4JN29wN20KtDE3/EbsUyxXzTq4IyBDql\n\
	mftxmA7GVdtqZSIFxO/EXb7ubBJUU5F6SUKpbjcEJgqKH5AxCs72dPiv4w4i6/D+\n\
	FQ4tARDlDxZ9GTFL69YyjAOluSsQ0i/F51YUNI7rcZFfr1+0xGupo/lCx4v6QQID\n\
	AQABo10wWzAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBTxP6PlaJPFU/sF+uErM4tj\n\
	NegdUjAfBgNVHSMEGDAWgBTxP6PlaJPFU/sF+uErM4tjNegdUjALBgNVHQ8EBAMC\n\
	AYYwDQYJKoZIhvcNAQELBQADgYEAHq+u+k9s8D/DFM36aXqeIgQBnrESB8aj+qFt\n\
	jVYLw4QpyVn93duwv3KOFybsP870UjQWRp5uBJSulu3DSSNalYFNNrI0IAyByfWU\n\
	jdD5pvtMzVCkEtAQ33fRvxRmNEYLIU3Tb1Q0tDP20o22J4+jcz5zSun7RoaCCdpP\n\
	DX4Zm48=\n\
	-----END CERTIFICATE-----";
	size_t mlen = 0, len = 0, tmplen = 0, tmplen2 = 0;

	const unsigned char key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
	unsigned char iv[16] = {0};
	unsigned char out[4096] = {0};
	unsigned char plain[4096] = {0};
	size_t olen = 4096;
	CIPHER_PCTX h;
	const unsigned char *p = NULL;
	unsigned char *pout = NULL;
	size_t split_len = 128;
	int mode[] = {CIPHER_PADDING_MODE_PKCS7, CIPHER_PADDING_MODE_ONE_AND_ZEROS, CIPHER_PADDING_MODE_ZEROS_AND_LEN,		//填充模式
					CIPHER_PADDING_MODE_ZEROS};
	const char *padding_desc[] = {"pkcs7 padding", "one_and_zeros padding", "zeros_and_len padding", "zeros padding"};
	int i = 0, ret =0;

	for (i = 0; (unsigned int)i < sizeof(mode)/sizeof(int); i ++)
	{
		printf("testing cipher(sm4) mode(cbc) padding mode(%s) ..........",  
	       padding_desc[i]);

		memset(out, 0, sizeof(out));
		memset(plain, 0, sizeof(plain));
		tmplen = 0, tmplen2 = 0;
		olen = sizeof(out);
		h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
		if(!h){
			printf("out of memory\n");
			return ;
		}

		p = (unsigned char *)message;
		mlen = strlen(message);
		len = mlen;
		pout = out;
		
		ret = cipher_set_key(h, key, sizeof(key), 1);
		s_assert( (ret == 0), "set key failed. %08x\n", ret);
		ret = cysec_cipher_set_iv(h, iv, sizeof(iv));			//ecb模式还用设置初始化向量吗？？？
		s_assert( (ret == 0), "set iv failed. %08x\n", ret);
		ret = cysec_cipher_set_padding_mode(h, mode[i]);
		s_assert( (ret == 0), "set mode failed. %08x\n", ret);
		ret = cysec_cipher_init(h);
		s_assert( (ret == 0), "init failed. %08x\n", ret);
		while(len)
		{
			tmplen = olen;
			if( len >= split_len) {
				ret = cysec_cipher_update(h, p, split_len, pout, &tmplen);
				s_assert( (ret == 0), "update failed. %08x\n", ret);
				p += split_len;
				pout += tmplen;
				olen -= tmplen;
				len -= split_len;
				tmplen2 += tmplen;
			} else {
				ret = cysec_cipher_update(h, p, len, pout, &tmplen);
				s_assert( (ret == 0), "update failed. %08x\n", ret);
				p += len;
				tmplen2 += tmplen;
				len -= len;
				pout += tmplen;
				olen -= tmplen;
			}
		}

		ret = cysec_cipher_final(h, pout, &tmplen);
		s_assert( (ret == 0), "final failed. %08x\n", ret);
		tmplen2 += tmplen;
		cipher_ctx_free(h);

		h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
		if(!h) {
			printf("out of memory\n");
			return ;
		}

		ret = cipher_set_key(h, key, cysec_cipher_key_size(CIPHER_ALG_SM4_CBC), 0);
		s_assert( (ret == 0), "set key. %08x\n", ret);
		ret = cysec_cipher_set_iv(h, iv, cysec_cipher_iv_size(CIPHER_ALG_SM4_CBC));
		s_assert( (ret == 0), "set iv. %08x\n", ret);
		tmplen = sizeof(plain);
		ret = cysec_cipher_set_padding_mode(h, mode[i]);
		s_assert( (ret == 0), "set mode. %08x\n", ret);		
		ret = cipher_cbc(h, plain, &tmplen, out, tmplen2);
		s_assert( (ret == 0), "cbc. %08x\n", ret);		
		cipher_ctx_free(h);

		if ( memcmp(plain, message, tmplen ) != 0 || mlen != tmplen ) {
			printf("failed.\n");
		} else
			printf("success.\n");

	}
}
/**
	使用非填充模式对明文进行多轮分组加密，使用cbc模式进行解密
 */
void test_cipher_padding_mode_none1(void)
{
	printf("******使用非填充模式对明文进行多轮分组加密，使用cbc模式进行解密******\n");
	unsigned char message[16*28] = {0};
	size_t mlen = 0, len = 0, tmplen = 0, tmplen2 = 0;

	const unsigned char key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
	unsigned char iv[16] = {0};
	unsigned char out[4096] = {0};
	unsigned char plain[4096] = {0};
	size_t olen = 4096;
	CIPHER_PCTX h;
	const unsigned char *p = NULL;
	unsigned char *pout = NULL;
	size_t split_len = 128;
	int ret = 0;
	unsigned int i = 0;

	h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
	if(!h){
		printf("out of memory\n");
		return ;
	}

	for (i = 0; i < sizeof(message); i++) message[i] = i;

	p = (unsigned char *)message;
	mlen = sizeof(message);
	len = mlen;
	pout = out;
	
	ret = cipher_set_key(h, key, sizeof(key), 1);
	s_assert( (ret == 0), "set key failed. %08x\n", ret);
	ret = cysec_cipher_set_iv(h, iv, sizeof(iv));
	s_assert( (ret == 0), "set iv failed. %08x\n", ret);
	ret = cysec_cipher_set_padding_mode(h, CIPHER_PADDING_MODE_NONE);
	s_assert( (ret == 0), "set padding mode failed. %08x\n", ret);
	ret = cysec_cipher_init(h);
	s_assert( (ret == 0), "init failed. %08x\n", ret);
	while(len)
	{
		tmplen = olen;
		if( len >= split_len) {
			ret = cysec_cipher_update(h, p, split_len, pout, &tmplen);
			p += split_len;
			pout += tmplen;
			olen -= tmplen;
			len -= split_len;
			tmplen2 += tmplen;
		} else {
			ret = cysec_cipher_update(h, p, len, pout, &tmplen);
			p += len;
			tmplen2 += tmplen;
			len -= len;
			pout += tmplen;
			olen -= tmplen;
		}
	}

	ret = cysec_cipher_final(h, pout, &tmplen);
	s_assert( (ret == 0), "final failed. %08x\n", ret);
	tmplen2 += tmplen;
	cipher_ctx_free(h);

	h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
	if(!h) {
		printf("out of memory\n");
		return ;
	}

	ret = cipher_set_key(h, key, cysec_cipher_key_size(CIPHER_ALG_SM4_CBC), 0);
	s_assert( (ret == 0), "set key failed. %08x\n", ret);
	ret = cysec_cipher_set_iv(h, iv, cysec_cipher_iv_size(CIPHER_ALG_SM4_CBC));
	s_assert( (ret == 0), "set iv failed. %08x\n", ret);
	ret = cysec_cipher_set_padding_mode(h, CIPHER_PADDING_MODE_NONE);
	s_assert( (ret == 0), "set padding mode failed. %08x\n", ret);	
	tmplen = sizeof(plain);
	ret = cipher_cbc(h, plain, &tmplen, out, tmplen2);
	s_assert( (ret == 0), "cbc failed. %08x\n", ret);
	cipher_ctx_free(h);

	if ( memcmp(plain, message, tmplen ) != 0 || mlen != tmplen) {
		printf("test cbc(update) none padding failed.\n");
	} else
		printf("test cbc(update) none padding success.\n");
}

/**
	使用cbc非填充模式对明文进行多轮分组加密，使用cbc模式进行解密
 */
void test_cipher_padding_mode_none2(void)
{
	printf("******使用cbc非填充模式对明文进行多轮分组加密，使用cbc模式进行解密******\n");
	unsigned char message[16*28] = {0};
	size_t mlen = 0, len = 0, tmplen = 0, tmplen2 = 0;

	const unsigned char key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
	unsigned char iv[16] = {0};
	unsigned char out[4096] = {0};
	unsigned char plain[4096] = {0};
	size_t olen = 4096;
	CIPHER_PCTX h;
	const unsigned char *p = NULL;
	unsigned char *pout = NULL;
	size_t split_len = 128;
	int ret = 0;
	unsigned int i = 0;

	h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
	if(!h){
		printf("out of memory\n");
		return ;
	}

	for (i = 0; i < sizeof(message); i++) message[i] = i;

	p = (unsigned char *)message;
	mlen = sizeof(message);
	len = mlen;
	pout = out;
	
	ret = cipher_set_key(h, key, sizeof(key), 1);
	s_assert( (ret == 0), "set key failed. %08x\n", ret);
	ret = cysec_cipher_set_iv(h, iv, sizeof(iv));
	s_assert( (ret == 0), "set iv failed. %08x\n", ret);
	ret = cysec_cipher_set_padding_mode(h, CIPHER_PADDING_MODE_NONE);
	s_assert( (ret == 0), "set padding mode failed. %08x\n", ret);
	while(len)
	{
		tmplen = olen;
		if( len >= split_len) {
			ret = cipher_cbc(h, pout, &tmplen, p, split_len);
			p += split_len;
			pout += tmplen;
			olen -= tmplen;
			len -= split_len;
			tmplen2 += tmplen;
		} else {
			ret = cipher_cbc(h, pout, &tmplen, p, len );
			p += len;
			tmplen2 += tmplen;
			len -= len;
			pout += tmplen;
			olen -= tmplen;
		}
	}

	cipher_ctx_free(h);
	h = cipher_ctx_new(CIPHER_ALG_SM4_CBC);
	if(!h) {
		printf("out of memory\n");
		return ;
	}

	ret = cipher_set_key(h, key, cysec_cipher_key_size(CIPHER_ALG_SM4_CBC), 0);
	s_assert( (ret == 0), "set key failed. %08x\n", ret);
	ret = cysec_cipher_set_iv(h, iv, cysec_cipher_iv_size(CIPHER_ALG_SM4_CBC));
	s_assert( (ret == 0), "set iv failed. %08x\n", ret);
	ret = cysec_cipher_set_padding_mode(h, CIPHER_PADDING_MODE_NONE);
	s_assert( (ret == 0), "set padding mode failed. %08x\n", ret);
	tmplen = sizeof(plain);
	ret = cipher_cbc(h, plain, &tmplen, out, tmplen2);
	s_assert( (ret == 0), "cbc failed. %08x\n", ret);
	cipher_ctx_free(h);

	if ( memcmp(plain, message, tmplen ) != 0 || mlen != tmplen) {
		printf("test cbc(cbc) none padding failed.\n");
	} else
		printf("test cbc(cbc) none padding success.\n");
}

int main(void) {
	test_cipher_cbc_encdec();
	test_cipher_padding_mode();
	test_cipher_padding_mode_none1();
	test_cipher_padding_mode_none2();
	test_cipher_ecb_benchmark();
	test_cipher_cbc_benchmark();
	return 0;
}
