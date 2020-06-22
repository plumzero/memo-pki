#ifndef __SYAN_CYSEC_CLIENT_SDK_H__
#define __SYAN_CYSEC_CLIENT_SDK_H__

/**
 * \mainpage Cyber SDK 2.0l
 * \author 江苏先安科技有限公司 (c) 2016-2017 All rights reserved
 *
 * \section intro_sec 简介
 *
 * CyberSDK是江苏先安科技有限公司开发的一套C语言密码应用开发库, 包含以下特性:
 * \li 支持SHA256, MD5, SHA384, SM3数据摘要算法
 * \li 支持AES, SM4对称加密算法
 * \li 支持RSA, ECC, SM2等非对称密码算法
 * \li 支持RSA/ECC/SM2数字证书解析, 证书链管理, 验证
 * \li 支持TLS 1.2客户端通讯协议
 * \li 完全独立于openssl等开源crypt/ssl实现, 提供商业授权.
 * \li [与openssl函数对照表](openssl.md)
 *
 * \section chlog_sec 修改记录
 *
 * 2018/4/2 v2.0l
 * \li 新增cysec_scep_request_renewalreq_new函数用于SCEP证书更新接口。
 *
 * 2018/3/8 v2.0k
 * \li 增加cysec_certmgr_add_capath函数
 * \li 根据超时来调整cysec_tls_client_set_fd使用模式
 * \li 修复cysec_tls_client_get_ssl_session bug
 * \li 新增cysec_tls_client_ssl_session_free函数
 *
 * 2017/12/29 v2.0j
 * \li 增加cysec_cipher_set_padding_mode支持多种对称加密padding类型
 * \li 修复一个加载私钥（带口令）的BUG
 *
 * 2017/12/27 v2.0i
 * \li 新增cysec_pkcs7_sign函数,提供PKCS7 各种模式的签发
 * \li 调整对称加解密API，具体为：
 * \li 调整cysec_cipher_set_key函数，新增cysec_cipher_set_iv函数，
 * \li 新增多轮加密函数cysec_cipher_init, cysec_cipher_update, cysec_cipher_final
 * \li 新增AES128，AES192 ECB模式
 * 
 * 2017/12/24 v2.0h
 * \li 由于项目需求重新添加ASN1解码相关函数及测试程序
 * \li 针对不同平台添加不同config.h文件
 *
 * 2017/12/18 v2.0g
 * \li 支持QNX平台
 * \li 修复多线程下一些问题
 *
 * 2017/12/7 v2.0f
 * \li 修复了在非阻塞模式下不能获取SSL Alert Code的错误。
 * \li 修复了非阻塞模式下tls_client_write无限制返回WANT_READ问题
 *
 * 2017/11/20 v2.0e
 * \li 修复一个cysec_pkcs7_SignedAndEnveloped_open不返回签发者证书的bug
 *
 * 2017/11/15 v2.0d
 * \li 修复了一个在某些情况下改变系统时区的BUG
 * \li 新增cysec_tls_client_set_block_mode函数,可以随时调整阻塞或者非阻塞
 * \li 在网络信道不好时，使用cysec_tls_client_set_rwtimeout 调整读写超时来增加读写数据可靠性。
 *
 * 2017/11/13 v2.0c
 * \li 修复cysec_x509req_new在特定情况下失败的bug
 * \li 修复test_scep一个bug
 *
 * 2017/9/5 v2.0b
 * \li 新增ECC相关函数 cysec_pkey_gen_ecc_by_name，cysec_pkey_ecc_get_curve_name
 *
 * 2017/9/3 v2.0a
 * \li 新增数字信封封包，解包功能
 *
 * 2017/9/1 v2.0
 * \li 开发新的V2.0底层框架，更加稳定，更适合车载平台以及嵌入式设备，单片机
 * \li 高度可定制的网络，随机数，各种回调适应各种硬件平台
 * \li 删除ASN1解析相关函数
 * \li 调整证书/证书签发请求 主题项输入方式(从/C=CN/O=SYAN/OU=SYAN/CN=TEST 到 CN=TEST,OU=SYAN,O=SYAN,C=CN)
 * \li 调整证书/证书签发请求 序列号为16进制输入（01：02：03）
 * \li 调整cysec_pkey_gen_ecc 函数入参，新增多种椭圆曲线参数
 * \li 调整cysec_ocsprsp_get_certstatus函数获取指定证书的证书状态（支持多个证书状态）
 * \li 删除cysec_ocsprsp_decode_ex 函数
 * \li 增加cysec_ocsprsp_get_certstatus_ex函数用于调整ocsp response有效时间
 *
 * 2017/8/3 v1.5j
 * \li 增加 cysec_tls_client_connect_by_socket 函数
 * \li 调整 cysec_tls_client_shutdown 关闭SSL隧道，不关闭socket
 * \li 调整 cysec_tls_client_close 关闭SSL隧道，关闭socket
 * \li 新增 socket 连接demo
 * \li 新增 cysec_set_global_random 设置全局外部随机数函数

 * 2017/6/14 v1.5i
 * \li 修复RSA验证签名BUG
 *
 * 2017/4/7 v1.5h
 * \li 修复使用socket方式进行SSL握手有时候没正确关闭网络socket情况
 * \li 更改cysec_tls_client_tcp_connect函数原型，调整函数返回值含义
 * \li 修复当阻塞于某个慢系统调用的一个进程捕获某个信号且相应信号处理函数返回时，该系统调用可能会返回一个EINTR错误,增加部分错误码
 *
 * 2017/3/28 v1.5g
 * \li 修复使用socket方式进行SSL握手产生阻塞情况
 * \li 增加使用socket方式设置超时函数
 *
 * 2017/2/14 v1.5f
 * \li 增加一个参数放宽OCSP Stapling中时间范围检测，增加实用性(cysec_ocsprsp_decode_ex)。
 *
 * 2017/1/10 v1.5e
 * \li 修复一个1.5c引入的读取指定随机数发生器设备节点的BUG
 * \li 调整了部分SCEP解码错误码使其更贴近逻辑
 *
 * 2017/1/9 v1.5d
 * \li 增加ASN1部分解码函数
 * \li 调整SM2 SCEP signerInfo扩展性中MessageType OID
 *
 * 2017/1/4 v1.5c
 * \li 增加读取指定随机数发生器设备节点,(/dev/hwrng)
 * \li 修复加载证书BUG（证书扩展性SubjectAltName类型为OtherName:OCT类型)
 *
 * 2016/12/26 v1.5b
 * \li 增加SHA512杂凑算法支持
 * \li PKCS#1 签名验证函数支持SHA512杂凑算法
 * \li 增加cysec_pkey_digest_sign 函数中传入RSA X509_SIG 类型支持
 * \li X509_REQ设置SubjectALtName 使用otherName类型

 * 2016/12/20 v1.5a
 * \li 增加tls相关函数接口来适配libcurl
 * \li 增加SHA1杂凑算法支持
 * \li 修复SCEP请求一些BUG
 *
 * 2016/12/19 v1.4b
 * \li 修改PKCS#1 原签名，验签接口，增加摘要算法参数。
 * \li 增加新PKCS#1接口，用于外部进行杂凑，传入杂凑值。
 * \li 增加SM2签名杂凑算法适配PKCS#1 新接口。
 * \li 增加MD5杂凑算法支持
 *
 * 2016/12/09 v1.4a
 * \li 增加PKCS7验签接口（支持RSA，SM2，ECC）
 *
 * 2016/12/07 v1.3b
 * \li 增加SCEP接口（支持SM2）
 *
 * 2016/11/30 v1.3a
 * \li 增加SCEP接口(支持RSA)
 *
 * 2016/11/27 v1.2d
 * \li 增加证书签发请求(PKCS10)接口
 *
 * 2016/11/18 v1.2c
 * \li 增加支持硬件签名
 *
 * 2016/11/14 v1.2b
 * \li 增加公私钥导出功能
 *
 * 2016/10/31 v1.2a
 * \li 增加ocsp客户端,支持ocspstapling（支持sm2,ecc,rsa)
 *
 * 2016/10/26 v1.1b
 * \li 修复bug: aes-cbc解密错误
 * \li 修复bug: rsa无法生成512位以上长度的密钥
 * \li samples\shgm.c: 增加对应的测试和示例代码
 *
 * 2016/6/25 v1.1a
 * \li hash增加SHA256的支持
 * \li tls客户端新增函数: tls_client_get_peer_certificate(), tls_client_get_ciphername()
 * \li 新增HMAC相关函数. 注意: 目前尚未支持hmac-sm3
 * \li 新增openssl兼容函数(include/cysec/openssl/ssh.h), 支持libcurl(请参阅源码目录下的contrib). 注意: 服务端证书验证尚未完成
 * \li 新增随机数生成函数cysec_random_generate()
 *
 * 2016/5/31 v1.0d
 * \li 完成性能测试所需接口函数
 *
 */

#ifdef __cplusplus
  extern "C" {
#endif

/**
 * 所有返回为CYSEC_RET的函数, 均以0表示成功, 其他表示失败
 */
typedef int CYSEC_RET;

///////////////////////////////
#define CYSEC_VERSION 0x0002000b //2.0k
#define CYSEC_VERSION_STRING "2.0k"

/**
 * 获取当前sdk版本
 * @return CYSEC_VERSION
 */
unsigned int cysec_version(void);

/**
 * @brief 回调随机数函数（用户实现）
 * @param p_arg 为用户数据，如果没用，设置为NULL
 * @param buf, 已分配buffer
 * @param bszie buffer 尺寸
 */
typedef int (*cysec_random_func_ptr)(void *p_arg, unsigned char *buf, size_t bsize);

/**
 * 设置随机数获取回调
 * @param p_func int p_func(void *p_arg, unsigned char *buffer, size_t buffersize) 函数原型
 * @param p_arg 回调函数参数
 * @return 0 成功， 非0失败
 */
CYSEC_RET cysec_set_global_random(cysec_random_func_ptr p_func,void *p_arg);

/**
 * 生成随机数
 * @param  buf 缓冲区, 用于存放生成的随机数
 * @param  num 期望的随机数字节数
 * @return     成功 -> 0, 失败 -> 其它
 */
CYSEC_RET cysec_random_generate(unsigned char* buf, size_t num);

typedef struct pkey_ctx_st* PKEY_PCTX;
typedef struct digest_ctx_st DIGEST_CTX;
typedef DIGEST_CTX* DIGEST_PCTX;

typedef enum {
	HASH_ALG_AUTO = 0,     /** 用于RSA签名验签函数内部检测算法 */
	HASH_ALG_SHA384 = 1,  /**< SHA384摘要算法 */
	HASH_ALG_SM3    = 2,  /**< SM3摘要算法 */
	HASH_ALG_SHA256 = 3,   /**< SHA256摘要算法 */
	HASH_ALG_MD5 = 4,		/**< MD5摘要算法 */
	HASH_ALG_ECDSA_SM2 = 5, /**< SM2签名摘要算法，只用于SM2签名，验签作用，不适用HMAC等 */
	HASH_ALG_SHA1 = 6,		/**< SHA1摘要算法 */
	HASH_ALG_SHA512 = 7 	/**< SHA512摘要算法 */
} HASH_ALG;

/**
 * @brief 构造hash算法句柄. 类似于openssl中EVP_MD_CTX_init() + EVP_get_digestbynid()
 * @param  halg 算法标识
 * @return      成功返回指定算法的hash算法句柄, 失败返回NULL
 */
DIGEST_PCTX cysec_digest_ctx_new(HASH_ALG halg);
/**
 * 释放hash算法句柄. 类似于openssl中的EVP_MD_CTX_cleanup()
 * @param ctx 待释放的hash算法句柄
 */
void cysec_digest_ctx_free(DIGEST_PCTX ctx);

/**
 * 返回指定hash算法的结果大小(byte), 类似于openssl中的EVP_MD_size()
 * @param  halg 算法标识
 * @return      >0 成功
 */
unsigned int cysec_digest_size(HASH_ALG halg);

/**
 * hash运算初始化, 类似于openssl中EVP_Digest_Init()
 * @param  ctx hash算法句柄
 * @param  pkey SM2证书公钥句柄PKEY_CTX(只对SM2签名算法有效，在对SM2签名算法做杂凑时必须设置，其他为NULL)
 * @return     0成功, 其它失败
 */
CYSEC_RET cysec_digest_init(DIGEST_PCTX ctx, PKEY_PCTX pkey);
/**
 * 执行hash运算, 可以多次调用, 类似于openssl中EVP_DigestUpdate()
 * @param  ctx hash算法句柄
 * @param  buf 输入数据
 * @param  len 输入数据长度
 * @return     0成功, 其它失败
 */
CYSEC_RET cysec_digest_update(DIGEST_PCTX ctx, const unsigned char* buf, size_t len);
/**
 * 获取hash计算的结果. 类似于openssl中的EVP_DigestFinal()
 * @param  ctx    hash算法句柄
 * @param  digest hash计算结果
 * @return        0成功, 其它失败
 */
CYSEC_RET cysec_digest_final(DIGEST_PCTX ctx, unsigned char* digest);

////////////////////////////////

typedef struct hmac_ctx_st HMAC_CTX;
typedef HMAC_CTX* HMAC_PCTX;

/**
 * @brief 构造hmac算法句柄. 类似于openssl中HAMC_CTX_init() + EVP_get_digestbynid()
 * @param  halg 算法标识
 * @return      成功返回指定算法的hmac算法句柄, 失败返回NULL
 */
HMAC_PCTX cysec_hmac_ctx_new(HASH_ALG halg);
/**
 * 释放hmac算法句柄. 类似于openssl中的EVP_MD_CTX_cleanup()
 * @param ctx 待释放的hmac算法句柄
 */
void cysec_hmac_ctx_free(HMAC_PCTX ctx);
/**
 * 返回指定hmac算法的结果大小(byte), 类似于openssl中的HMAC_size()
 * @param  ctx hmac算法句柄
 * @return      >0 成功
 */
unsigned int cysec_hmac_size(HMAC_PCTX ctx);
/**
 * 获取hmac接受的最大密钥长度
 * @return 密钥长度
 */
unsigned int cysec_hmac_key_maxsize();
/**
 * hmac运算初始化, 类似于openssl中HMAC_Init()
 * @param  ctx hmac算法句柄
 * @param  key 密钥
 * @param  keylen 密钥长度
 * @return     0成功, 其它失败
 */
CYSEC_RET cysec_hmac_init(HMAC_PCTX ctx, const unsigned char* key, int keylen);
/**
 * 执行hmac运算, 可以多次调用, 类似于openssl中HMAC_Update()
 * @param  ctx hmac算法句柄
 * @param  buf 输入数据
 * @param  len 输入数据长度
 * @return     0成功, 其它失败
 */
CYSEC_RET cysec_hmac_update(HMAC_PCTX ctx, const unsigned char* buf, size_t len);
/**
 * 获取hmac计算的结果. 类似于openssl中的HMAC_Final()
 * @param  ctx    hmac算法句柄
 * @param  hmac   hmac计算结果
 * @return        0成功, 其它失败
 */
CYSEC_RET cysec_hmac_final(HMAC_PCTX ctx, unsigned char* hmac);

///////////////////////////////

typedef struct cipher_ctx_st* CIPHER_PCTX;

typedef enum {
	CIPHER_ALG_AES128_ECB = 1,  /**< AES128 对称加密算法 ECB模式 */
	CIPHER_ALG_AES192_ECB = 2,  /**< AES192 对称加密算法 ECB模式 */
	CIPHER_ALG_AES256_ECB = 3,  /**< AES256 对称加密算法 ECB模式 */
	CIPHER_ALG_AES128_CBC = 4,  /**< AES128 对称加密算法 CBC模式 */
	CIPHER_ALG_AES192_CBC = 5,  /**< AES192 对称加密算法 CBC模式 */
	CIPHER_ALG_AES256_CBC = 6,  /**< AES256 对称加密算法 CBC模式 */
	CIPHER_ALG_SM4_ECB    = 7,  /**< SM4对称加密算法 ECB模式 */
	CIPHER_ALG_SM4_CBC 	  = 8,  /**< SM4对称加密算法 CBC模式 */
} CIPHER_ALG;

typedef enum {
	CIPHER_PADDING_MODE_PKCS7 = 0, /**< PKCS7 padding (default)  */
	CIPHER_PADDING_MODE_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding */
	CIPHER_PADDING_MODE_ZEROS_AND_LEN, /**< ASNI X.923 padding */
	CIPHER_PADDING_MODE_ZEROS,	/**< zero padding */
	CIPHER_PADDING_MODE_NONE /**< never pad */
} CIPHER_PADDING_MODE;
/**
 * 构造加密算法句柄. 类似openssl中EVP_CIPHER_CTX_init() + EVP_get_cipherbynid()
 * @param  calg 对称加密算法标识
 * @return      成功->加密算法句柄; 失败->NULL
 */
CIPHER_PCTX cysec_cipher_ctx_new(CIPHER_ALG calg);
/**
 * 释放对称加密句柄. 类似openssl中EVP_CIPHER_CTX_cleanup()
 * @param ctx 对称加密算法句柄
 */
void cysec_cipher_ctx_free(CIPHER_PCTX ctx);

/**
 * 获取对称加密算法block长度. 类似openssl中EVP_CIPHER_block_size()
 * @param  calg 对称加密算法标识
 * @return      该算法block长度
 */
unsigned int cysec_cipher_block_size(CIPHER_ALG calg);
/**
 * 获取对称加密算法key长度. 类似openssl中EVP_CIPHER_key_size()
 * @param  calg 对称加密算法标识
 * @return      该算法key长度
 */
unsigned int cysec_cipher_key_size(CIPHER_ALG calg);
/**
 * 获取对称加密算法iv长度. 类似openssl中EVP_CIPHER_iv_size()
 * @param  calg 对称加密算法标识
 * @return      该算法iv长度
 */
unsigned int cysec_cipher_iv_size(CIPHER_ALG calg);
/**
 * 设置密钥. 类似openssl中的EVP_CipherInit_ex()
 * @param  ctx     对称加密句柄
 * @param  key     key
 * @param  klen    key长度
 * @param  encrypt 1 -> 加密; 0 -> 解密
 * @return         0 -> 成功
 */
int cysec_cipher_set_key(CIPHER_PCTX ctx, const unsigned char* key, size_t klen, int encrypt);

/**
 * 设置IV，如果是ECB模式，则不用调用，用于CBC模式等其他模式
 * @param ctx 对称加密句柄
 * @param iv IV
 * @param ivlen iv长度
 * @return 0成功， 非0失败
 */
int cysec_cipher_set_iv(CIPHER_PCTX ctx, const unsigned char* iv, size_t ivlen);

/**
 * 设置cipher padding 类型
 * @param ctx 对称加密句柄
 * @param mode padding mode
 * @return 0成功， 非0失败
 */
int cysec_cipher_set_padding_mode(CIPHER_PCTX ctx, CIPHER_PADDING_MODE mode);

/**
 * 多轮对称加密初始化
 * @param ctx 对称加密句柄
 * @return 0成功，非0失败
 */
int cysec_cipher_init(CIPHER_PCTX ctx);

/**
 * 多轮加密update
 * @param ctx 对称加密句柄
 * @param input 待加密明文数据
 * @param ilen 明文数据长度
 * @param output 已分配的加密数据buffer, 必须大于ilen + block_size, 而且不能与input相同
 * @param olen 输出时加密后结果长度
 * @return 0 成功,非0 失败
 */
int cysec_cipher_update(CIPHER_PCTX ctx, const unsigned char *input, size_t ilen, 
		unsigned char *output, size_t *olen);

/**
 * 多轮加密finish
 * @param ctx 对称加密句柄
 * @param output 已分配的buffer, 至少一个block_size长度
 * @param olen 输出时加密后结果长度
 * @return 0 成功,非0 失败
 */
int cysec_cipher_final(CIPHER_PCTX ctx, unsigned char *output, size_t *olen);

/**
 * 执行CBC模式的对称加密算法. 类似openssl中的EVP_Cipher(), 一次性加密
 * @param  ctx     对称加密句柄
 * @param  out     返回数据缓冲区, 由调用者分配
 * @param  olen    返回数据缓冲区长度
 * @param  in      输入数据
 * @param  ilen    输入数据长度
 * @return         0 -> 成功
 */
CYSEC_RET cysec_cipher_cbc(CIPHER_PCTX ctx, unsigned char* out, size_t* olen, const unsigned char* in, size_t ilen);

///////////////////////////////
typedef int (*cysec_password_cb)(char*, int, int, void*);

typedef enum{
	DER = 1,  /**< DER编码 */
	PEM = 2	  /**< PEM编码 */
}CERTTYPE;

typedef enum{
	ECC_CURVE_NONE = 0,	/**< NONE */
	ECC_CURVE_SECP256R1, /**< NIST SCEP256R1曲线 */
	ECC_CURVE_SECP384R1, /**< NIST SCEP384R1曲线 */
	ECC_CURVE_SECP521R1, /**< NIST SCEP521R1曲线 */
	ECC_CURVE_SM2 /**< SM2 */
}PKEY_ECC_CURVE;
/**
 * 生成rsa私钥(公钥包含在私钥里面)
 * @param  bits 密钥长度
 * @return      成功->密钥句柄; 失败->NULL
 */
PKEY_PCTX cysec_pkey_gen_rsa(unsigned int bits);

/**
 * 生成sm2私钥(公钥包含在私钥里面)
 * @return      成功->密钥句柄; 失败->NULL
 */
PKEY_PCTX cysec_pkey_gen_sm2();

/**
 * 生成ecc私钥(公钥包含在私钥里面)
 * @param  curve_id PKEY_ECC_CURVE
 * @return      成功->密钥句柄; 失败->NULL
 */
PKEY_PCTX cysec_pkey_gen_ecc(PKEY_ECC_CURVE curve_id);

/**
 * 生成ecc公私钥
 * @param curve_name ("none",
 *		"secp256r1",
 *		"secp384r1",
 *		"secp521r1",
 *		"sm2",)
 * @return 成功->密钥句柄; 失败->NULL
*/
PKEY_PCTX cysec_pkey_gen_ecc_by_name(const char *curve_name);

/**
 * 获取ECC 椭圆曲线参数名称
 * @param ctx 密钥
 * @return NULL失败，非NULL成功
 */
const char *cysec_pkey_ecc_get_curve_name(const PKEY_PCTX ctx);	

/**
 * 从缓冲区构造私钥
 * @param  buf DER或者PEM格式的RSA/SM2/ECC密钥数据
 * @param  len 缓冲区长度
 * @param  passwd 私钥保密口令
 * @return     失败->NULL
 */
PKEY_PCTX cysec_pkey_load_private(const unsigned char* buf, size_t len, const char* passwd);
/**
 * 从缓冲区构造公钥
 * @param  buf DER或者PEM格式的RSA/SM2/ECC密钥数据
 * @param  len 缓冲区长度
 * @return     NULL -> 失败
 */
PKEY_PCTX cysec_pkey_load_public(const unsigned char* buf, size_t len);
/**
 * 释放密钥句柄. 类似openssl的EVP_PKEY_free()
 * @param ctx [description]
 */
void cysec_pkey_free(PKEY_PCTX ctx);

/**
 * 返回密钥长度 (bits方式) 例如sm2应返回256
 * @param  ctx
 * @return     密钥长度. <=0 -> 失败
 */
int cysec_pkey_get_bits(const PKEY_PCTX ctx);
/**
 * 判断当前密钥句柄是否是rsa密钥
 * @param  ctx 密钥句柄
 * @return     0 -> 不是; >0 -> 是
 */
int cysec_pkey_is_rsa(const PKEY_PCTX ctx);
/**
 * 判断当前密钥句柄是否是sm2密钥
 * @param  ctx 密钥句柄
 * @return     0 -> 不是; >0 -> 是
 */
int cysec_pkey_is_sm2(const PKEY_PCTX ctx);
/**
 * 判断当前密钥句柄是否是ecc密钥. 注意, 如果是sm2密钥, 这里会返回"是"
 * @param  ctx 密钥句柄
 * @return     0 -> 不是; >0 -> 是
 */
int cysec_pkey_is_ecc(const PKEY_PCTX ctx);
/**
 * 判断当前密钥句柄是否是私钥.
 * @param  ctx 密钥句柄
 * @return     0 -> 不是; >0 -> 是
 */
int cysec_pkey_is_private(const PKEY_PCTX ctx);

/**
 * 导出公钥
 * @param ctx 密钥句柄
 * @param out 密钥
 * @param olen 密钥长度
 * @param type 输出类型，默认(der)
 * @return 0->成功, 非0->失败
 */
int cysec_pkey_export_publickey(const PKEY_PCTX ctx, unsigned char **out, size_t *olen, CERTTYPE type);

/**
 * 导出私钥
 * @param ctx 密钥句柄
 * @param out 密钥
 * @param olen 密钥长度
 * @param type 输出类型，默认(der)
 * @return 0->成功, 非0->失败
 */
int cysec_pkey_export_privatekey(const PKEY_PCTX ctx, unsigned char **out, size_t *olen, CERTTYPE type);

/**
 * 公钥加密
 * @param  ctx    密钥句柄
 * @param  in     明文缓冲区
 * @param  inlen  明文长度
 * @param  out    密文缓冲区
 * @param  outlen [in]密文缓冲区长度, [out]密文长度
 * @return        成功->0, 失败->其它
 */
CYSEC_RET cysec_pkey_public_encrypt(PKEY_PCTX ctx, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);
/**
 * 私钥解密
 * @param  ctx    密钥句柄
 * @param  in     密文缓冲区
 * @param  inlen  密文长度
 * @param  out    明文缓冲区
 * @param  outlen [in]明文缓冲区长度, [out]明文长度
 * @return        成功->0, 失败->其它
 */
CYSEC_RET cysec_pkey_private_decrypt(PKEY_PCTX ctx, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);
/**
 * 私钥签名
 * @param  ctx    密钥句柄
 * @param  in     待签名数据
 * @param  inlen  待签名数据长度
 * @param  halg   摘要算法（RSA,ECC 可以设置MD5, SHA1, SHA256，SHA384, SHA512 算法，SM2证书只接受ECDSA_SM2算法）
 * @param  sig    DER编码的签名结果. 如果是RSA算法, 返回PKCS#1, 如果是ECC/SM2返回对应的ECDSA签名结果
 * @param  siglen 签名结果长度
 * @return        0 -> 成功; 其它 -> 失败
 */
CYSEC_RET cysec_pkey_sign(PKEY_PCTX ctx, const unsigned char* in, size_t inlen, HASH_ALG halg, unsigned char* sig, size_t* siglen);

/**
 * 公钥验证签名
 * @param  ctx    密钥句柄
 * @param  in     原始数据
 * @param  inlen  原始数据长度
 * @param  halg   摘要算法（RSA,ECC 可以设置MD5, SHA1, SHA256，SHA384, SHA512算法，SM2证书只接受ECDSA_SM2算法）
 * @param  sig    DER编码的签名
 * @param  siglen 签名长度
 * @return        0 -> 成功; 其它 -> 失败
 */
CYSEC_RET cysec_pkey_verify(PKEY_PCTX ctx, const unsigned char* in, size_t inlen, HASH_ALG halg, const unsigned char* sig, size_t siglen);

/**
 * 私钥签名
 * @param  ctx    密钥句柄
 * @param  digest  待签名数据在外部进行摘要运算所得到的HASH结果
 * @param  dlen   HASH长度
 * @param  halg   摘要算法（RSA,ECC 可以设置MD5, SHA1, SHA256, SHA384, SHA512, AUTO(自动检测)算法，SM2证书只接受ECDSA_SM2算法）
 * @param  sig    DER编码的签名结果. 如果是RSA算法, 返回PKCS#1, 如果是ECC/SM2返回对应的ECDSA签名结果
 * @param  siglen 签名结果长度
 * @return        0 -> 成功; 其它 -> 失败
 */
CYSEC_RET cysec_pkey_digest_sign(PKEY_PCTX ctx, const unsigned char* digest, size_t dlen, HASH_ALG halg, unsigned char* sig, size_t* siglen);

/**
 * 公钥验证签名
 * @param  ctx    密钥句柄
 * @param  digest 待签名数据在外部进行摘要运算所得到的HASH结果
 * @param  dlen	  HASH长度
 * @param  halg   摘要算法（RSA,ECC 可以设置MD5, SHA1, SHA256， SHA384, SHA512, AUTO(自动检测）算法，SM2证书只接受ECDSA_SM2算法）
 * @param  sig    DER编码的签名
 * @param  siglen 签名长度
 * @return        0 -> 成功; 其它 -> 失败
 */
CYSEC_RET cysec_pkey_digest_verify(PKEY_PCTX ctx, const unsigned char* digest, size_t dlen, HASH_ALG halg, const unsigned char* sig, size_t siglen);
///////////////////////////////

typedef struct x509crt_ctx_st  X509CRT_CTX;
typedef X509CRT_CTX* X509CRT_PCTX;

/**
 * 从字符串缓冲区构造证书. 无需指定格式, 自动支持der或pem格式的输入
 * @param  buf 证书内容
 * @param  len 数据长度
 * @return     失败->NULL, 成功->证书句柄
 */
X509CRT_PCTX cysec_x509crt_load(const unsigned char* buf, size_t len);
/**
 * 释放证书句柄
 * @param x509 证书句柄
 */
void cysec_x509crt_free(X509CRT_PCTX x509);
/**
 * 获取证书主题项
 * @param  x509 证书句柄
 * @return      证书主题项
 */
const char* cysec_x509crt_get_subject(const X509CRT_PCTX x509);
/**
 * 获取证书签发者项
 * @param  x509 证书句柄
 * @return      证书签发者项
 */
const char* cysec_x509crt_get_issuer(const X509CRT_PCTX x509);
/**
 * 获取证书序列号
 * @param  x509 证书句柄
 * @return      证书序列号(十六进制格式)
 */
const char* cysec_x509crt_get_sn(const X509CRT_PCTX x509);
/**
 * 获取证书生效日期. YYYYMMDDHHmmssZ格式
 * @param  x509 证书句柄
 * @return      证书生效日期(YYYYMMDDHHmmssZ格式)
 */
const char* cysec_x509crt_get_notbefore(const X509CRT_PCTX x509);
/**
 * 获取证书失效日期. YYYYMMDDHHmmssZ格式
 * @param  x509 证书句柄
 * @return      证书失效日期(YYYYMMDDHHmmssZ格式)
 */
const char* cysec_x509crt_get_notafter(const X509CRT_PCTX x509);
/**
 * 获取证书公钥
 * @param  x509 证书句柄
 * @return      证书公钥
 */
PKEY_PCTX cysec_x509crt_get_publickey(const X509CRT_PCTX x509);
/**
 * 对证书做der格式编码
 * @param  x509   证书句柄
 * @param  outlen 结果长度
 * @return        der格式的证书内容
 */
const unsigned char* cysec_x509crt_as_der(const X509CRT_PCTX x509, int* outlen);
/**
 * 对证书做pem格式编码
 * @param  x509   证书句柄
 * @return        pem格式的证书内容
 */
const char* cysec_x509crt_as_pem(const X509CRT_PCTX x509);
///////////////////////////////
typedef struct x509req_ctx_st* X509REQ_PCTX;

/**
 * 构造证书签发请求句柄
 * @param pkey 密钥句柄
 * @return 返回证书请求句柄
 */
X509REQ_PCTX cysec_x509req_new(const PKEY_PCTX pkey);

/** 
 * 释放证书签发请求句柄
 * @param ctx 证书签发请求句柄
 */
void cysec_x509req_free(X509REQ_PCTX ctx);

/**
 * 设置证书签发请求主题项
 * @param ctx 证书签发请求句柄
 * @param subject 主题项
 * @return 0 > 正常 非0 > 失败
 */
CYSEC_RET cysec_x509req_set_subject_name(X509REQ_PCTX ctx, const char *subject);

/**
 * 设置证书签发请求序列号
 * @param ctx 证书签发请求句柄
 * @param sn 序列号(16进制,xx:xx:xx:xx)
 * @return 0 > 正常 非0 > 失败
 */
CYSEC_RET cysec_x509req_set_serialnumber(X509REQ_PCTX ctx, const char *sn);

/**
 * 开启Subject Key ID 
 * @param ctx 证书签发请求句柄
 * @return 0 > 正常 非0 > 失败
 */
CYSEC_RET cysec_x509req_enable_skid(X509REQ_PCTX ctx);

/**
 * 设置challengepw
 * @param ctx 证书签发请求句柄
 * @param challengepw 
 * @return 0 > 正常 非0 > 失败
 */
CYSEC_RET cysec_x509req_set_challengepw(X509REQ_PCTX ctx, const char *challengepw);
/**
 * 签发证书签发请求
 * @param ctx 证书签发请求句柄
 * @return 0 > 正常 非0 > 失败
 */
CYSEC_RET cysec_x509req_sign(X509REQ_PCTX ctx);

/**
 * 导出证书签发请求
 * @param ctx 证书签发请求句柄
 * @param out 输出buffer
 * @param olen 输出长度
 * @param type 输出类型
 * @return 0 > 正常， 非0 失败
 */
CYSEC_RET cysec_x509req_export(const X509REQ_PCTX ctx, unsigned char **out, size_t *olen, CERTTYPE type);

/** 
 * 设置Suject Alt Name 
 * @param ctx 证书签发请求句柄
 * @param altname SubjectAltName 值
 * @param altnameSz SubjectAltName 长度
 * @return 0 > 正常， 非0 失败
 */
CYSEC_RET cysec_x509req_set_altname(X509REQ_PCTX ctx, const unsigned char *altname, size_t altnameSz);

/**
 * 从证书签发请求签发自签名证书
 * @param ctx 证书签发请求句柄
 * @return 自签名证书， NULL失败
 */
X509CRT_PCTX cysec_x509req_to_x509(X509REQ_PCTX ctx);
///////////////////////////////

typedef struct certmgr_ctx_st* CERTMGR_PCTX;

/**
 * 构造证书管理器. 类似openssl的X509_STORE_new()
 * @return NULL -> 失败
 */
CERTMGR_PCTX cysec_certmgr_new();
/**
 * 关闭证书管理器. 类似openssl的X509_STORE_free()
 * @param ctx 证书管理器句柄
 */
void cysec_certmgr_free(CERTMGR_PCTX ctx);

/**
 * @brief 向证书管理器添加CA证书.
 * 被添加的CA证书将被用来验证证书链. 本函数可以被多次调用, 添加不同的CA证书, 支持多种证书链. 类似openssl的X509_STORE_add_cert()
 * @param  ctx   证书管理器句柄
 * @param  cacrt CA证书
 * @return 0 -> 成功; 其它 -> 失败
 */
CYSEC_RET cysec_certmgr_add_ca(CERTMGR_PCTX ctx, const X509CRT_PCTX cacrt);

/**
 * @brief 向证书管理器添加CA证书路径.
 * 被添加的CA证书路径将被用来验证证书链，会把路径中所有证书加载到证书管理器中。
 * @param  ctx   证书管理器句柄
 * @param  capath CA证书路径
 * @return 0 -> 成功; 其它 -> 失败
 */
CYSEC_RET cysec_certmgr_add_capath(CERTMGR_PCTX ctx, const char *capath);

/**
 * 验证证书
 * @param  ctx 证书管理器句柄
 * @param  crt 待验证证书
 * @return     0 -> 验证通过; 其它 -> 失败
 */
CYSEC_RET cysec_certmgr_verify(CERTMGR_PCTX ctx, const X509CRT_PCTX crt);

///////////////////////////////

typedef struct tls_client_ctx_st* TLS_CLIENT_PCTX;

/**
 * 构造tls客户端句柄 （默认是非阻塞模式）
 * @return 成功 -> tls客户端句柄, 失败 -> NULL
 */
TLS_CLIENT_PCTX cysec_tls_client_new();
 
 /**
  * 设置读写超时(默认120秒)
  * @param ctx tls客户端句柄
  * @param timeout 超时，-1 为阻塞，0位非阻塞，>0 超时秒数
  * @return 0 成功
  */
int cysec_tls_client_set_rwtimeout(TLS_CLIENT_PCTX ctx, long timeout);

/**
 * 设置阻塞模式或者非阻塞模式
 * @param ctx tls客户端句柄
 * @param blockmode 1为阻塞模式
 * @return 成功 -> 0, 失败 -> 其它
 */
CYSEC_RET cysec_tls_client_set_block_mode(TLS_CLIENT_PCTX ctx, int blockmode);

/**
 * 释放tls客户端句柄
 * @param ctx tls客户端句柄
 */
void cysec_tls_client_free(TLS_CLIENT_PCTX ctx);
/**
 * 设置客户端证书
 * @param  ctx tls客户端句柄
 * @param  crt 客户端证书
 * @return     成功 -> 0, 失败 -> 其它
 */
CYSEC_RET cysec_tls_client_set_certificate(TLS_CLIENT_PCTX ctx, const X509CRT_PCTX crt);
/**
 * 设置客户端私钥
 * @param  ctx tls客户端句柄
 * @param  key 客户端私钥
 * @return     成功 -> 0, 失败 -> 其它
 */
CYSEC_RET cysec_tls_client_set_private_key(TLS_CLIENT_PCTX ctx, const PKEY_PCTX key);

/**
 * @brief set CA chain
 * @param ctx tls context
 * @param ca_chain the CA chain
 * @param * reserved
 * @return success->0 ,or error code
 */
CYSEC_RET cysec_tls_client_set_ca_chain(TLS_CLIENT_PCTX ctx, const CERTMGR_PCTX ca_chain, void *);

/**
 * 获取服务端数字证书
 * @param  ctx tls客户端句柄
 * @return     成功 -> 服务端证书, 失败 -> NULL
 */
X509CRT_PCTX cysec_tls_client_get_peer_certificate(TLS_CLIENT_PCTX ctx);
/**
 * 获取通信采用的对称算法名称
 * @param  ctx tls客户端句柄
 * @return     对称算法名称
 */
const char* cysec_tls_client_get_ciphername(TLS_CLIENT_PCTX ctx);

/**
 * 设置证书链验证回调函数（用于SDK使用者自己实现所需功能）
 * @param crt 	服务端证书
 * @param userdata 使用者数据，使用者可以根据自己需求设置userdata
 * @return 期待 0 为验证成功， CYSEC_TLS_CLIENT_VERIFY_PEER_CERTIFICATE_ERROR 为失败
 */
typedef CYSEC_RET (*cysec_certverify_callback)(X509CRT_PCTX crt, void* userdata);

/** 
 * 设置OCSP Stapling 服务端证书验证回调函数（用于SDK使用者自己实现所需功能）
 * @param crt 服务端证书
 * @param ocspresponse OCSP响应数据
 * @param olen OCSP响应数据长度
 * @param userdata 使用者数据，使用者可以根据自己需求设置userdata
 * @return 期待 0 为验证成功，CYSEC_TLS_CLIENT_VERIFY_SERVER_CERTIFICATE_STATUS_ERROR为失败
 */
typedef CYSEC_RET (*cysec_ocspstapling_callback)(X509CRT_PCTX crt, unsigned char *ocspresponse, int olen, void *userdata);

#define CYSEC_TLS_CLIENT_SIGN_ERROR	-0x7600
/**
 * 设置SSL隧道中签名函数回调
 * @param in 	带签名数据
 * @param ilen 	带签名数据长度
 * @param out 	签名数据【已分配】
 * @param olen 	已分配数据长度
 * @param userdata 用户数据，使用者根据自己需求设置userdata
 * @return 期待 0 为签名成功， 非0失败
 */
typedef CYSEC_RET (*cysec_sign_callback)(const unsigned char *in, size_t ilen, unsigned char *out, size_t *olen, void *userdata);
/**
 * 设置服务端证书验证回调函数
 * @param  ctx      tls客户端句柄
 * @param  cb       回调函数
 * @param  userdata 用户自定义数据
 * @return          验证通过 -> 0, 失败 -> 其它
 */
CYSEC_RET cysec_tls_client_set_verify_callback(TLS_CLIENT_PCTX ctx, cysec_certverify_callback cb, void* userdata);

/**
 * 设置服务端证书ocsp stapling回调函数
 * @param ctx  		tls客户端句柄
 * @param cb 		回调函数
 * @param userdata  用户自定义数据
 * @return			通过 ->0, 失败 -> 其他
 */
int cysec_tls_client_set_ocspstapling_callback(TLS_CLIENT_PCTX ctx, cysec_ocspstapling_callback cb, void *userdata);

/**
 * 设置私钥签名回调函数
 * @param ctx 	tls客户端句柄
 * @param cb 	回调函数
 * @param userdata 	用户自定义数据
 * @return 		通过 ->0, 失败 -> 其他
 */
int cysec_tls_client_set_pkey_sign_callback(TLS_CLIENT_PCTX ctx, cysec_sign_callback cb, void *userdata);

/**
 * 打开tls客户端连接
 * @param  ctx  tls客户端句柄
 * @param  host 对端地址(可以也是IP地址, 也可以是主机名)
 * @param  port 对端端口
 * @return 0 成功，非0失败
 */
CYSEC_RET cysec_tls_client_connect(TLS_CLIENT_PCTX ctx, const char* host, int port);

/**
 * 使用socket连接SSL客户端
 * @param ctx tls客户端句柄
 * @param sockfd 已经建立的socket fd
 * @return 0 成功, 非0失败
 */
int cysec_tls_client_connect_by_socket(TLS_CLIENT_PCTX ctx, int sockfd);

/**
 * 发送数据
 * @param  ctx tls客户端句柄
 * @param  buf 待发送数据
 * @param  len 待发送数据的长度
 * @return     实际发送的数据长度, 返回负数可以通过cysec_tls_client_get_sslerror获取原因
 */
int cysec_tls_client_write(TLS_CLIENT_PCTX ctx, const unsigned char* buf, size_t len);
/**
 * 接收数据
 * @param  ctx tls客户端句柄
 * @param  buf 接收数据缓冲区
 * @param  len 接收数据缓冲区的长度
 * @return     实际接收的数据长度，返回负数可以通过cysec_tls_client_get_sslerror获取原因
 */
int cysec_tls_client_read(TLS_CLIENT_PCTX ctx, unsigned char* buf, size_t len);
/**
 * 关闭tls客户端连接
 * @param  ctx tls客户端句柄
 * @return     成功 -> 0; 失败 -> 其它
 */
CYSEC_RET cysec_tls_client_close(TLS_CLIENT_PCTX ctx);

/////////////////////////////////////////////
// 为libCurl适配新增函数
/////////////////////////////////////////////

#ifndef NO_CURL_SUPPORT
/**
 * @brief 使用socket套接字连接主机
 * @param host 主机名可以是ip地址或者主机名
 * @param port 端口
 * @param sockfd 连接成功后的socket file description 
 * @return 非0 失败
 */
int cysec_tls_client_tcp_connect(const char *host, int port, int *sockfd);

/**
 * @brief 设置socket套接字号
 * @param ctx tls句柄
 * @param sockfd socket filedescription
 * @return 0 > 成功 非0失败
 */
int cysec_tls_client_set_fd(TLS_CLIENT_PCTX ctx, int sockfd);

/**
 * @brief 构造一个SSL句柄（适配libcurl相关函数）
 * @param ctx tls 句柄
 * @return 0 > 成功 非0失败
 */
int cysec_tls_client_ssl_new(TLS_CLIENT_PCTX ctx);

/**
 * @brief 设置SSL相关（适配libcurl相关函数）
 * @param ctx tls 句柄
 * @return 0 > 成功，非0失败
 */
int cysec_tls_client_ssl_setup_conf(TLS_CLIENT_PCTX ctx);

/**
 * @brief 连接ssl隧道
 * @param ctx tls句柄
 *
 * @note 非阻塞，TCP_NODELAY
 * @return 0 > 成功 非0 > 失败
 */
int cysec_tls_client_ssl_connect(TLS_CLIENT_PCTX ctx);

/**
 * @brief 获取SSL Session信息
 * @param ctx tls句柄
 * @return 非NULL 成功， NULL失败
 */
void *cysec_tls_client_get_ssl_session(TLS_CLIENT_PCTX ctx);

/**
 * @brief 设置SSL Session信息
 * @param ctx tls 句柄
 * @param sslsession SSL Session
 * @return 0 > 成功, 非0 > 失败
 */
int cysec_tls_client_set_ssl_session(TLS_CLIENT_PCTX ctx, void *sslsession);

/**
 * @brief 释放SSL Session 信息
 * @param sslsession SSL session
 */
void cysec_tls_client_ssl_session_free(void *sslsession);

/**
 * @brief 获取SSL alert码
 * @param ctx tls client 句柄
 * @return -1 为失败
 */
int cysec_tls_client_get_alert_code(TLS_CLIENT_PCTX ctx);

/**
 * @brief 获取SSL 隧道错误码
 * @param ctx tls 句柄
 * @param err 当前错误码
 * @return SSL错误码
 */
int cysec_tls_client_get_sslerror(TLS_CLIENT_PCTX ctx, int err);

#define CYSEC_TLS_CLIENT_ERROR_STRING_MAX_SZ 80
/**
 * @brief 获取SSL错误串
 * @param err cysec_tls_client_get_sslerror获取的错误码
 * @param buf 传入buffer,长度小于CYSEC_TLS_CLIENT_ERROR_STRING_MAX_SZ
 * @return buf
 */
char *cysec_tls_client_get_sslerror_string(int err, char *buf);

/**
 * @brief 获取目前从SSL隧道中可读的字节数
 * @param ctx tls 句柄
 * @return 字节数
 */
int cysec_tls_client_pending(TLS_CLIENT_PCTX ctx);

/**
 * @brief 关闭SSL隧道
 * @param ctx tls 句柄
 * @return 0 > 成功 非0 > 失败
 */
int cysec_tls_client_shutdown(TLS_CLIENT_PCTX ctx);

/**
 * @brief 设置检查证书域名或IP（当设置验证对端证书时有效)
 * @param ctx tls 句柄
 * @param domain 域名或者IP地址
 * @return 0 > 成功， 非0 >失败
 */
int cysec_tls_client_check_domain_name(TLS_CLIENT_PCTX ctx, const char *domain);

#ifdef HAVE_ALPN
/**
 * @brief 设置隧道使用ALPN协议
 * @param ctx tls 句柄
 * @param protocol 协议
 * @param plen 协议长度
 * @return 0 > 成功， 非0 > 失败
 */
int cysec_tls_client_use_ALPN(TLS_CLIENT_PCTX ctx, char *protocol, unsigned short plen);

/**
 * @brief 获取支持的ALPN协议
 * @param ctx tls 句柄
 * @param protocol 协议
 * @param plen 协议长度
 * @return 0 > 成功， 非0 > 失败
 */
int cysec_tls_client_ALPN_get_protocol(TLS_CLIENT_PCTX ctx, char **protocol, unsigned short *plen);
#endif

#ifdef HAVE_SUPPORTED_CURVES
/**
 * @brief 设置使用支持的椭圆曲线
 * @param ctx tls 句柄
 * @param name 0x17(secp256r1), 0x18(secp384r1) ,0x19(secp521r1)
 */
int cysec_tls_client_use_supported_curve(TLS_CLIENT_PCTX ctx, unsigned short name);
#endif

#ifdef HAVE_SNI
/**
 * @brief 设置server name indication
 * @param ctx tls 句柄
 * @param name 服务器名称
 * @param nlen 服务器名称长度
 * @return 0 > 成功 非0 > 失败
 */
int cysec_tls_client_use_SNI(TLS_CLIENT_PCTX ctx, char *name, unsigned short nlen);
#endif

#endif //NO_CURL_SUPPORT

////////////////////////////////////////////
////////////////////////////////////////////
typedef struct ocsp_request_ctx_st* OCSP_REQUEST_PCTX;
typedef struct ocsp_response_ctx_st* OCSP_RESPONSE_PCTX;

/**
 * 释放OCSP_REQUEST_CTX句柄
 * @param ctx ocsp请求句柄
 */
void cysec_ocspreq_free(OCSP_REQUEST_PCTX *ctx);

/**
 * 构造ocsp请求句柄
 * @param ctx 待验证证书句柄
 * @param cm 证书管理器句柄
 * @return 成功 -> tls句柄，失败 -> NULL
 */
OCSP_REQUEST_PCTX cysec_ocspreq_new(X509CRT_PCTX ctx, CERTMGR_PCTX cm);

/**
 * 对ocsp进行编码
 * @param ctx ocsp请求句柄
 * @param out 输出ocsp请求编码
 * @param olen 输出ocsp请求编码长度
 * @return 成功 -> 0, 失败 -> 非0 
 */
CYSEC_RET cysec_ocspreq_encode(OCSP_REQUEST_PCTX ctx, unsigned char **out, size_t *olen);

/**
 * 释放ocsp响应句柄
 * @param ctx ocsp响应句柄
 */
void cysec_ocsprsp_free(OCSP_RESPONSE_PCTX *ctx);

/**
 * 解码ocsp响应
 * @param in ocsp响应
 * @param ilen ocsp响应长度
 * @param ctx ocsp响应句柄
 * @return 成功 -> 0， 失败 -> 非0 
 */
CYSEC_RET cysec_ocsprsp_decode(const unsigned char *in, size_t ilen, OCSP_RESPONSE_PCTX *ctx);

/**
 * 从ocsp响应获取签发者证书
 * @param ctx ocsp响应句柄
 * @return 成功 -> 返回签发者证书句柄 失败 -> NULL
 */
X509CRT_PCTX cysec_ocsprsp_get_signer(OCSP_RESPONSE_PCTX ctx);

/**
 * 获取ocsp响应码
 * @param ctx ocsp响应句柄
 * @param status 返回rsp响应码 0 -> ok, 1->Illegal confirmation 2->internal error 
 * 3->try again later 5->sig required 6->unauthroized
 * @return 成功 ->0 , 失败 -> 非0
 */
int cysec_ocsprsp_get_rspstatus(OCSP_RESPONSE_PCTX ctx, unsigned int *status);

/**
 * 获取ocsp响应证书状态码
 * @param ctx ocsp响应句柄
 * @param x509 要查询证书
 * @param cm 证书管理器
 * @param status 返回证书状态码 0 -> good ,1 -> revoked, 2 -> unknown
 * @return 成功 ->0, 失败 -> 非0
 */ 
int cysec_ocsprsp_get_certstatus(OCSP_RESPONSE_PCTX ctx, X509CRT_PCTX x509, CERTMGR_PCTX cm, unsigned int *status);

/**
 * 获取ocsp响应证书状态码
 * @param ctx ocsp响应句柄
 * @param x509 要查询证书
 * @param cm 证书管理器
 * @param t 宽容时间 0检测OCSP响应，>0 为增加误差范围多少秒（秒）
 * @param status 返回证书状态码 0 -> good ,1 -> revoked, 2 -> unknown
 * @return 成功 ->0, 失败 -> 非0
 */
 int cysec_ocsprsp_get_certstatus_ex(OCSP_RESPONSE_PCTX ctx, X509CRT_PCTX x509, CERTMGR_PCTX cm, long t,
	unsigned int *status);
/**
 * 检测ocsp请求和ocsp响应是否匹配
 * @param req ocsp请求句柄
 * @param rsp ocsp响应句柄
 * @return 成功 -> 0, 失败 -> 非0
 */
int cysec_ocsprsp_check(OCSP_REQUEST_PCTX req, OCSP_RESPONSE_PCTX rsp);

/**
 * 验证ocsp响应
 * @param ctx ocsp响应句柄
 * @param x509 ocsp签发者证书
 * @return 成功 -> 0, 失败 -> 非0
 */
int cysec_ocsprsp_verify(OCSP_RESPONSE_PCTX ctx, X509CRT_PCTX x509);

/**
 * 获取ocsp响应中的签发者证书
 * @param ctx 证书管理器句柄
 * @param rsp OCSP响应句柄
 * @return  非空 -> 获取成功； NULL -> 失败
 */
X509CRT_PCTX cysec_certmgr_get_ocsprsp_signer(CERTMGR_PCTX ctx, OCSP_RESPONSE_PCTX rsp);

///////////////////////////////
typedef struct scep_request_ctx_st* SCEP_REQUEST_PCTX;
typedef struct scep_response_ctx_st* SCEP_RESPONSE_PCTX;

/**
 * 构造SCEP 客户端新发证书请求句柄
 * @param csr 证书签发请求句柄
 * @param clientcrt 客户端证书句柄（自签名证书）
 * @param clientpkey 客户端私钥句柄
 * @param cacrt CA证书句柄
 * @return 返回SCEP客户端请求句柄 NULL失败
 */
SCEP_REQUEST_PCTX cysec_scep_request_pkcsreq_new(const X509REQ_PCTX csr, const X509CRT_PCTX clientcrt, 
		const PKEY_PCTX clientpkey, const X509CRT_PCTX cacrt);

/**
 * 构造SCEP 客户端更新证书请求具柄
 * @param csr 证书签发请求句柄
 * @param clientcrt 客户端证书句柄（老证书）
 * @param clientpkey 客户端私钥句柄 (老私钥)
 * @param cacrt CA证书句柄
 * @return 返回SCEP客户端请求句柄 NULL失败
 */
SCEP_REQUEST_PCTX cysec_scep_request_renewalreq_new(const X509REQ_PCTX csr, const X509CRT_PCTX clientcrt, 
		const PKEY_PCTX clientpkey, const X509CRT_PCTX cacrt);

/**
 * SCEP 客户端请求编码
 * @param ctx SCEP客户端请求句柄
 * @param out 输出编码(DER)
 * @param olen 输出编码长度 
 * @return 0 > 正常 非0 > 失败
 */
CYSEC_RET cysec_scep_request_encode(SCEP_REQUEST_PCTX ctx, unsigned char **out, size_t *olen);

/**
 * 释放SCEP客户端请求句柄
 * @param ctx SCEP客户端请求句柄
 */
void cysec_scep_request_free(SCEP_REQUEST_PCTX ctx);

/**
 * 释放SCEP响应句柄
 * @param ctx SCEP客户端响应句柄
 */
void cysec_scep_response_free(SCEP_RESPONSE_PCTX ctx);

/**
 * 构造SCEP响应句柄
 * @param clientpkey 客户端私钥句柄
 * @param clientcert 客户端证书句柄
 * @return SCEP响应句柄
 */
SCEP_RESPONSE_PCTX cysec_scep_response_certrep_new(const X509CRT_PCTX clientcert, const PKEY_PCTX clientpkey);

/**
 * 解码SCEP响应句柄
 * @param der DER编码响应
 * @param dlen 响应长度
 * @param ctx SCEP响应句柄
 * @return 正常 > 0, 失败 > 非0
 */
CYSEC_RET cysec_scep_response_decode(const unsigned char *der, size_t dlen, SCEP_RESPONSE_PCTX ctx);

/**
 * 获取响应类型
 * @param ctx SCEP响应句柄
 * @return WOLFSSL_SCEP_MSG_CERTREP 3
 */
int cysec_scep_response_get_messagetype(const SCEP_RESPONSE_PCTX ctx);

/**
 * 获取SCEP响应状态
 * @param ctx SCEP响应句柄
 * @return 0 成功 2 失败 3 Pending
 */
int cysec_scep_response_get_pkistatus(const SCEP_RESPONSE_PCTX ctx);

/**
 * 获取SCEP错误原因
 * @param ctx SCEP响应句柄
 * @return 0(BADALG) 1(BADMESSAGECHECK) 2(BADREQUEST) 3(BADTIME) 4(BADCERTID) 
 */
int cysec_scep_response_get_failinfo(const SCEP_RESPONSE_PCTX ctx);

/**
 * 检测SCEP NONCE 
 * @param req SCEP客户端请求句柄
 * @param rsp SCEP客户端响应句柄
 * @return 0 正常， 非0 失败
 */
int cysec_scep_check_nonce(SCEP_REQUEST_PCTX req, SCEP_RESPONSE_PCTX rsp);


/**
 * SCEP 响应数据签发证书验证回调
 * @param ctx 签发证书句柄
 * @param userdata 用户数据，使用者根据自己需求设置userdata
 * @return 期待 0 为验证成功， CYSEC_TLS_CLIENT_VERIFY_PEER_CERTIFICATE_ERROR 失败
 */
typedef CYSEC_RET (*cysec_verifysigner_callback)(X509CRT_PCTX ctx, void *userdata);

/**
 * 设置SCEP响应，验证签发者回调
 * @param ctx SCEP响应句柄
 * @param cb 回调函数
 * @param userdata 用户数据
 * @return 0 成功, 非0 失败
 */
int cysec_scep_response_set_verifysigner_callback(SCEP_RESPONSE_PCTX ctx, cysec_verifysigner_callback cb, void *userdata);
/**
 * 获取SCEP签发出的证书
 * @param ctx SCEP响应句柄
 * @return 证书， NULL失败
 */
X509CRT_PCTX cysec_scep_response_certrep_get_issuedcert(const SCEP_RESPONSE_PCTX ctx);

///////////////////////////////
/**
 * 验证PKCS7不带原文签名
 * @param plain 原文
 * @param plen 原文长度
 * @param pk7der PKCS7原文（DER）
 * @param pk7len PKCS7原文长度
 * @param x509 传出PKCS7中的X509证书
 * @return 0 > 验证通过 ， 非0 > 验证失败
 */
int cysec_pkcs7_detached_verify(const unsigned char *plain, size_t plen, 
									const unsigned char *pk7der, size_t pk7len, X509CRT_PCTX *x509);

/**
 * 验证PKCS7带原文签名
 * @param pk7der PKCS7原文（DER）
 * @param pk7len PKCS7原文长度
 * @param x509 传出PKCS7中的X509证书
 * @return 0 > 验证通过 ， 非0 > 验证失败
 */
int cysec_pkcs7_attached_verify(const unsigned char *pk7der, size_t pk7len, X509CRT_PCTX *x509);

#define CYSEC_PKCS7_FLAG_DETACHED 0x1
#define CYSEC_PKCS7_FLAG_ATTACHED 0x2
#define CYSEC_PKCS7_FLAG_WITH_ATTRIBUTES 0x4
#define CYSEC_PKCS7_FLAG_WITHOUT_ATTRIBUTES 0x8
/**
 * PKCS7签名
 * @param content the content which need be seal
 * @param clen the length of content
 * @param signer_pkey the signer pkey
 * @param signer_x509 the signer certificate
 * @param flags (CYSEC_PKCS7_FLAG_DETACHED | CYSEC_PKCS7_FLAG_ATTACHED) (CYSEC_PKCS7_FLAG_NO_ATTRIBUTES | CYSEC_PKCS7_FLAG_WITH_ATTRIBUTES)
 * @param seal output PKCS7
 * @param slen the length of slen
 * @param out_type certificate type
 *
 * @return 0 success or ERROR
 */
int cysec_pkcs7_sign(const unsigned char *content, size_t clen, PKEY_PCTX signer_pkey, X509CRT_PCTX signer_x509, int flags,
	unsigned char **seal, size_t *slen, CERTTYPE out_type);
/**
 * @brief open the PKCS7 
 *
 * @param pk7 the PKCS7 (pem or der)
 * @param pk7len the lenght of PKCS7
 * @param recip_cert the recipient certificate
 * @param recip_pkey the recipient private key
 * @param out output the plain buffer
 * @param olen output the length of plain buffer
 * @param signer_x509 output the signer certificate 
 * 
 * @return 0 success or ERROR
 */
int cysec_pkcs7_SignedAndEnveloped_open(const unsigned char *pk7, size_t pk7len, X509CRT_PCTX recip_cert, 
	PKEY_PCTX recip_pkey, 
	unsigned char **out, size_t *olen, X509CRT_PCTX *signer_x509);

/**
 * @brief seal the PKCS7
 *
 * @param content the content which need be seal
 * @param clen the length of content
 * @param recip_cert the recipient certificate
 * @param signer_pkey the signer pkey
 * @param signer_x509 the signer certificate
 * @param seal output PKCS7
 * @param slen the length of slen
 * @param out_type certificate type
 *
 * @return 0 success or ERROR
 */
int cysec_pkcs7_SignedAndEnveloped_seal(const unsigned char *content, size_t clen, X509CRT_PCTX recip_cert, 
	PKEY_PCTX signer_pkey, X509CRT_PCTX signer_x509,
	unsigned char **seal, size_t *slen, CERTTYPE out_type);

#ifndef CYSEC_NO_ASN1
///////////////////////////////
/**
 *	解析ASN1 SEQUNCE结构
 * @param input 数据指针
 * @param inOutIdx 索引，输入输出参数，输入时，函数从input+*inOutIdx处开始读数据，输出为input+*inOutIdx为SEQUENCE内容。
 * @param len 返回SEQUENCE长度
 * @param maxIdx input 长度
 * @return 0 > 成功， 非0 > 失败
 */
int cysec_asn1_get_sequence(const unsigned char *input, unsigned int *inOutIdx, int *len, size_t maxIdx);

/**
 * 从ASN1结构中获取版本信息
 * @param input 数据指针
 * @param inOutIdx 索引，输入输出参数，输入时，函数从input+*inOutIdx处开始读数据，输出为input+*inOutIdx为版本内容。
 * @param version 返回的版本号
 * @param maxIdx input 长度
 * @return 0 > 成功， 非0 > 失败
 */
int cysec_asn1_get_version(const unsigned char *input, unsigned int *inOutIdx, int *version, size_t maxIdx);

/**
 * 从ASN1结构中获取Octet String信息
 * @param input 数据指针
 * @param inOutIdx 索引，输入输出参数，输入时，函数从input+*inOutIdx处开始读数据，输出为input+*inOutIdx为Octet String内容。
 * @param len 返回octect String 内容长度
 * @param maxIdx input 长度
 * @return 0 > 成功， 非0 > 失败
 */
int cysec_asn1_get_octstring(const unsigned char  *input, unsigned int *inOutIdx, int *len, size_t maxIdx);

/**
 * 从ASN1结构中获取杂凑算法OID信息
 * @param input 数据指针
 * @param inOutIdx 索引，输入输出参数，输入时，函数从input+*inOutIdx处开始读数据，输出为input+*inOutIdx为OID内容。
 * @param maxIdx input 长度
 * @param alg 杂凑算法
 * @return 0 > 成功， 非0 > 失败
 */
int cysec_asn1_get_hashalg(const unsigned char *input, unsigned int *inOutIdx, size_t maxIdx, HASH_ALG *alg);
#endif

#define CYSEC_OK            0                  /**< CYSEC_RET返回值: 成功 */

#define CYSEC_E_BASE        0x10000000          /**< CYSEC_RET错误码掩码 */
#define CYSEC_E_UNSUPPORTED (CYSEC_E_BASE + 1)  /**< 当前操作尚未支持 */
#define CYSEC_E_INVALID_ARG (CYSEC_E_BASE + 2)  /**< 输入的参数有错误 */
#define CYSEC_E_INVALID_SIG (CYSEC_E_BASE + 3)  /**< 非法签名 */
#define CYSEC_E_MEMORY_E    (CYSEC_E_BASE + 4)  /** 内存分配失败 */

#define CYSEC_E_DIGEST_BASE        			0x11000000   /**< 摘要相关函数错误码掩码 */
#define CYSEC_E_CIPHER_BASE        			0x12000000   /**< 对称加密相关函数错误码掩码 */
#define CYSEC_E_CIPHER_IV_NOT_FOUND			CYSEC_E_CIPHER_BASE + 1
#define CYSEC_E_PKEY_BASE        			0x13000000   /**< 非对称密钥相关函数错误码掩码 */
#define CYSEC_E_PKEY_KEYTYPE_NOT_SUPPORT		(CYSEC_E_PKEY_BASE + 1) /**< 不支持的密钥类型 */
#define CYSEC_E_PKEY_TYPE_IS_NOT_MATCH_WITH_DIGESTTYPE (CYSEC_E_PKEY_BASE + 2) /**< 密钥类型与摘要算法不匹配 */
#define CYSEC_E_X509CRT_BASE       			0x14000000   /**< 数字证书相关函数错误码掩码 */
#define CYSEC_E_X509CRT_GET_PUBKEY 			(CYSEC_E_X509CRT_BASE + 1 ) /**< 获取证书公钥失败 */
#define CYSEC_E_INVALID_PEM_CERT				(CYSEC_E_X509CRT_BASE + 2 ) /**< 无效的PEM格式证书 */

#define CYSEC_E_CERTMGR_BASE       			0x15000000   /**< 证书管理器相关函数错误码掩码 */
#define CYSEC_E_TLSCLIENT_BASE     			0x16000000   /**< TLS客户端相关函数错误码掩码 */
#define CYSEC_E_TLSCLIENT_ALART_BASE			0x16500000	/**< TLSALART掩码 */
#define CYSEC_E_TLSCLIENT_BAD_CERTSTATUS 	0x16008000 	/** 证书状态错误 */

#define SGHM_E_TLSCLIENT_ALERT_BAD_CERT		0x1650002A	/**< bad certificate */
#define SGHM_E_TLSCLIENT_ALERT_UNSUPPORTED_CERT	0x1650002B	/**< unsupported certificate */
#define SGHM_E_TLSCLIENT_ALERT_REVOKED_CERT	0x1650002C	/** revoked certificate */
#define SGHM_E_TLSCLIENT_ALERT_EXPIRED_CERT 0x1650002D	/** expired certificate */
#define CYSEC_E_TLSCLIENT_ALART_UNKNOWN_CERT 0x1650002E	/** unknown certificate */

#define CYSEC_E_TLSCLIENT_PEER_REFUSE	  	(CYSEC_E_TLSCLIENT_BASE + 1) /**< 对方拒绝连接 */
#define CYSEC_E_TLSCLIENT_GET_LOCAL_CERTIFICATE	(CYSEC_E_TLSCLIENT_BASE + 2) /**< 获取本地证书失败 */
#define CYSEC_E_TLSCLIENT_INVALID_HOST		(CYSEC_E_TLSCLIENT_BASE + 3) /**< 无效的主机名 */
#define CYSEC_E_TLSCLIENT_INVALID_SOCKET		(CYSEC_E_TLSCLIENT_BASE + 4) /**< 无效的SOCKET */
#define CYSEC_E_TLSCLIENT_CONNECT_ERROR		(CYSEC_E_TLSCLIENT_BASE + 5) /**< 连接失败 */
#define CYSEC_E_TLSCLIENT_FAILED_TO_SET_SOCKET_NONBLOCK 	(CYSEC_E_TLSCLIENT_BASE + 6)
#define CYSEC_E_TLSCLIENT_FAILED_TO_SET_TCP_NODELAY 	(CYSEC_E_TLSCLIENT_BASE + 7)
#define CYSEC_E_TLSCLIENT_FCNTL_GETFL_ERROR 	(CYSEC_E_TLSCLIENT_BASE + 8)
#define CYSEC_E_TLSCLIENT_GET_PEER_CERTIFICATE_ERROR	(CYSEC_E_TLSCLIENT_BASE + 9)

#define CYSEC_E_RAND_BASE          			0x17000000   /**< 随机数相关函数错误码掩码 */
#define CYSEC_E_RAND_OPEN_ERROR				(CYSEC_E_RAND_BASE + 1) /** 打开随机数设备错误  */
#define CYSEC_E_RAND_READ_ERROR				(CYSEC_E_RAND_BASE + 2) /** 打读随机数错误  */
#define CYSEC_E_RAND_BLOCK_ERROR				(CYSEC_E_RAND_BASE + 3) /** 随机数设备阻塞  */
#define CYSEC_E_RAND_THREAD_INIT_ERROR		(CYSEC_E_RAND_BASE + 4) /** */
#define CYSEC_E_RAND_THREAD_DESTROY_ERROR	(CYSEC_E_RAND_BASE + 5) /** */
#define CYSEC_E_RAND_THREAD_LOCK_ERROR		(CYSEC_E_RAND_BASE + 6) /** */
#define CYSEC_E_RAND_THREAD_UNLOCK_ERROR		(CYSEC_E_RAND_BASE + 7)

#define CYSEC_E_OCSP_BASE		 			0x18000000		/**< OCSP相关函数错误码掩码 */
#define CYSEC_E_OCSP_NOT_FOUND_ISSUER		(CYSEC_E_OCSP_BASE + 1) /**< 找不到证书颁发着  */
#define CYSEC_E_X509REQ_BASE					0x19000000	/**< 证书签发相关函数错误码掩码 */
#define CYSEC_E_X509REQ_INVALID_SERIAL_NUMBER (CYSEC_E_X509REQ_BASE + 1) /**< 无效的序列号 */
#define CYSEC_E_SCEP_BASE					0x1a000000	/**< SCEP相关函数错误码掩码 */
#define CYSEC_E_PKCS7_BASE					0x1b000000	/**< PKCS7相关函数错误码掩码 */
#define CYSEC_E_PKCS7_CERT_NOT_FOUND			(CYSEC_E_PKCS7_BASE + 1) /** PKCS7中没有证书 */
#define CYSEC_E_PKCS7_INVALID_TYPE			(CYSEC_E_PKCS7_BASE + 2) /** PKCS7 类型  */
#define CYSEC_E_ASN1_BASE					0x1c000000 	/**< ASN1 相关错误码掩码 */
#define CYSEC_E_ASN1_HASH_OBJ_NOT_EXSIT_OR_HASH_ALG_NOT_SUPPORT	0x1c000001 /**< 不是HASH算法或HASH算法不支持 */
#define CYSEC_E_HMAC_BASE					0x1d000000  /**< HMAC 相关错误掩码 */

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#define random_generate		cysec_random_generate
#define digest_ctx_new		cysec_digest_ctx_new
#define digest_ctx_free		cysec_digest_ctx_free
#define digest_size		cysec_digest_size
#define digest_init		cysec_digest_init
#define digest_update		cysec_digest_update
#define digest_final		cysec_digest_final
#define hmac_ctx_new		cysec_hmac_ctx_new
#define hmac_ctx_free		cysec_hmac_ctx_free
#define hmac_size		cysec_hmac_size
#define hmac_key_maxsize		cysec_hmac_key_maxsize
#define hmac_init		cysec_hmac_init
#define hmac_update		cysec_hmac_update
#define hmac_final		cysec_hmac_final
#define cipher_ctx_new		cysec_cipher_ctx_new
#define cipher_ctx_free		cysec_cipher_ctx_free
#define cipher_block_size		cysec_cipher_block_size
#define cipher_key_size		cysec_cipher_key_size
#define cipher_iv_size		cysec_cipher_iv_size
#define cipher_set_key		cysec_cipher_set_key
#define cipher_cbc		cysec_cipher_cbc
#define pkey_gen_rsa		cysec_pkey_gen_rsa
#define pkey_gen_sm2		cysec_pkey_gen_sm2
#define pkey_gen_ecc		cysec_pkey_gen_ecc
#define pkey_load_private		cysec_pkey_load_private
#define pkey_load_public		cysec_pkey_load_public
#define pkey_free		cysec_pkey_free
#define pkey_get_bits		cysec_pkey_get_bits
#define pkey_is_rsa		cysec_pkey_is_rsa
#define pkey_is_sm2		cysec_pkey_is_sm2
#define pkey_is_ecc		cysec_pkey_is_ecc
#define pkey_is_private		cysec_pkey_is_private
#define pkey_public_encrypt		cysec_pkey_public_encrypt
#define pkey_private_decrypt		cysec_pkey_private_decrypt
#define pkey_sign		cysec_pkey_sign
#define pkey_verify		cysec_pkey_verify
#define x509crt_load		cysec_x509crt_load
#define x509crt_free		cysec_x509crt_free
#define x509crt_get_subject		cysec_x509crt_get_subject
#define x509crt_get_issuer		cysec_x509crt_get_issuer
#define x509crt_get_sn		cysec_x509crt_get_sn
#define x509crt_get_notbefore		cysec_x509crt_get_notbefore
#define x509crt_get_notafter		cysec_x509crt_get_notafter
#define x509crt_get_publickey		cysec_x509crt_get_publickey
#define x509crt_as_der		cysec_x509crt_as_der
#define x509crt_as_pem		cysec_x509crt_as_pem
#define certmgr_new		cysec_certmgr_new
#define certmgr_free		cysec_certmgr_free
#define certmgr_add_ca		cysec_certmgr_add_ca
#define certmgr_verify		cysec_certmgr_verify
#define tls_client_new		cysec_tls_client_new
#define tls_client_free		cysec_tls_client_free
#define tls_client_set_certificate		cysec_tls_client_set_certificate
#define tls_client_set_private_key		cysec_tls_client_set_private_key
#define tls_client_get_peer_certificate		cysec_tls_client_get_peer_certificate
#define tls_client_get_ciphername		cysec_tls_client_get_ciphername
#define tls_client_set_verify_callback		cysec_tls_client_set_verify_callback
#define tls_client_connect		cysec_tls_client_connect
#define tls_client_write		cysec_tls_client_write
#define tls_client_read		cysec_tls_client_read
#define tls_client_close		cysec_tls_client_close

#endif /* DOXYGEN_SHOULD_SKIP_THIS */

#ifdef __cplusplus
  }
#endif

#endif

