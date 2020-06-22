#ifndef __LIB_MBED_SM2_H
#define __LIB_MBED_SM2_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \mainpage MBEDSM2 SDK v0.0.2
 * \author 江苏先安科技有限公司 (c) 2018 All rights reserved
 *
 * \section intro_sec 简介
 *
 * MBEDSM2 SDK是江苏先安科技有限公司开发的一套C语言基于专利CN104243456（适用于
 * 云计算的基于SM2算法的签名及解密方法和系统的SDK库 包含以下特性:
 * \li 基于PandaSSL
 * \li 支持SM2生成公私钥对
 * \li 支持SM2签名算法
 * \li 支持SM2解密算法
 *
 * \section chlog_sec 修改记录
 * 2019/9/12 0.0.3
 * \li 增加加载密钥接口
 *
 * 2018/9/10 0.0.2
 * \li 增加导出私钥接口 
 *
 * 2018/7/19 0.0.1
 * \li 初始化
 */

#define LIBMBEDSM2_VERSION 0x00000003
#define LIBMBEDSM2_VERSION_STRING "0.0.3"

/**
 * @brief 返回库版本
 * @return 版本
 */
unsigned int mbedsm2_version(void );

/** 
 * Generate ecp key
 * Client ================================ Server 
 * 		----------P1(point string)------->
 *		<---------P(point string) --------
 */

typedef struct mbedsm2_pkey_st* MBEDSM2_PKEY_CTX;

/**
 * @brief 构造一个密钥句柄
 * @return NULL失败，非空成功
 */
MBEDSM2_PKEY_CTX libmbedsm2_pkey_new();

/**
 * @brief 客户端生成密钥Step one.
 *
 * @param pkey 客户端密钥句柄
 * @param out 输出的P1，外部传入buffer (大于等于67字节)
 * @param osize out大小
 * @param olen 输出真正的大小
 *
 * @note 输出未压缩的点P1
 * @return 0成功，非0失败
 */
int libmbedsm2_client_ecp_genkey_step_one( MBEDSM2_PKEY_CTX pkey, 
		unsigned char *out, size_t osize, size_t *olen );

/**
 * @brief 服务端生成密钥
 *
 * @param pkey 服务端密钥句柄
 * @param in 客户端输出的点p1
 * @param ilen 客户端输出的点p1长度
 * @param out 服务端输出P点，外部传入buffer,（大于等于67字节)
 * @param osize 外部传入buffer长度
 * @param olen 输出真正的长度
 *
 * @note 输出未压缩的点P
 * @return 0 成功，非0失败
 */
int libmbedsm2_server_ecp_genkey( MBEDSM2_PKEY_CTX pkey, 
		const unsigned char *in, size_t ilen, 
		unsigned char *out, size_t osize, size_t *olen);

/**
 * @brief 客户端生成密钥step two
 * 
 * @param pkey 客户端密钥句柄
 * @param in 服务端输出P点
 * @param ilen 服务端输出P点长度
 * 
 * @return 0 成功，非0失败
 */
int libmbedsm2_client_ecp_genkey_step_two( MBEDSM2_PKEY_CTX pkey, 
		const unsigned char *in, size_t ilen);

/**
 * @brief 导出公钥
 * 
 * @param pkey 密钥句柄
 * @param x x坐标,外部传入x buffer （大于等于32字节）
 * @param xsize 外部传入x buffer长度
 * @param xlen 输出x实际长度
 * @param y y坐标，外部传入y buffer （大于等于32字节）
 * @param ysize 外部传入y buffer长度
 * @param ylen 输出y实际长度
 *
 * @return 0 成功，非0失败
 */ 
int libmbedsm2_ecp_pkey_export_pubkey( MBEDSM2_PKEY_CTX pkey, 
		unsigned char *x, size_t xsize, size_t *xlen,
		unsigned char *y, size_t ysize, size_t *ylen);

/**
 * @brief 导出私钥
 *
 * @param pkey 私钥句柄
 * @param d 私钥
 * @param dsize 外部传入d长度
 * @param dlen 函数返回长度
 * 
 * @return 0成功，非0失败
 */
int libmbedsm2_ecp_pkey_export_private_key( MBEDSM2_PKEY_CTX pkey,
		unsigned char *d, size_t dsize, size_t *dlen);

/**
 * @brief 加载私钥
 * 
 * @param ctx 私钥句柄（初始化）
 * @param d 私钥数据
 * @param dlen 私钥数据长度
 * @param x 公钥x数据
 * @param xlen 公钥x数据长度
 * @param y 公钥y数据
 * @param ylen 公钥ylen数据长度
 *
 * @return 0 成功，非0失败
 */
int libmbedsm2_ecp_pkey_load(MBEDSM2_PKEY_CTX ctx,
	const unsigned char *d, size_t dlen,
	const unsigned char *x, size_t xlen,
	const unsigned char *y, size_t ylen);

/**
 * @brief 释放密钥句柄
 * 
 * @param pkey 密钥句柄
 */
void libmbedsm2_pkey_free(MBEDSM2_PKEY_CTX pkey);

/**
 *  Signature 
 *  Client ===================================== Server
 *  ---------------e, Q1(Point) -------------------->
 *  <--------------r, s2, s3 ------------------------
 *  Compute signature
 */

typedef struct mbedsm2_ecdsa_context_st* MBEDSM2_ECDSA_CONTEXT;

/**
 * @brief 构造签名相关句柄
 * 
 * @return NULL失败，非NULL成功.
 */
MBEDSM2_ECDSA_CONTEXT libmbedsm2_ecdsa_new();

/**
 * @brief sm2签名杂凑算法
 *
 * @param input 待杂凑数据
 * @param ilen 待杂凑数据长度
 * @param pkey 密钥句柄
 * @param output 输出buffer
 *
 * @return 0 成功，非0失败
 */
int mbedsm2_sm2hash( const unsigned char *input, size_t ilen, 
		MBEDSM2_PKEY_CTX key, unsigned char output[32]);

/**
 * @brief 客户端签名step one(已经预计算杂凑)
 *
 * @param ctx 签名句柄
 * @param pkey 客户端密钥句柄
 * @param Q1 输出未压缩Q1点，外部传入buffer （大于等于67字节)
 * @param q1size q1 buffer大小
 * @param q1len 输出Q1实际长度
 *
 * @note 0成功，非0失败
 */
int libmbedsm2_client_ecp_ecdsa_digest_sign_step_one( MBEDSM2_ECDSA_CONTEXT ctx, 
		MBEDSM2_PKEY_CTX pkey, 
		unsigned char *Q1, size_t q1size, size_t *q1len);

/**
 * @brief 客户端签名step one
 *
 * @param ctx 签名句柄
 * @param pkey 客户端密钥句柄
 * @param m 待签名消息
 * @param mlen 待签名消息长度
 * @param e 传入e buffer（大于等于32字节)
 * @param esize 传入e buffer大小
 * @param elen 输出e实际长度
 * @param Q1 输出未压缩Q1点，外部传入buffer （大于等于67字节)
 * @param q1size q1 buffer大小
 * @param q1len 输出Q1实际长度
 *
 * @note 0成功，非0失败
 */
int libmbedsm2_client_ecp_ecdsa_sign_step_one( MBEDSM2_ECDSA_CONTEXT ctx, 
		MBEDSM2_PKEY_CTX pkey, const unsigned char *m, size_t mlen,
		unsigned char *e, size_t esize, size_t *elen,
		unsigned char *Q1, size_t q1size, size_t *q1len);

/**
 * @brief 服务端签名
 * 
 * @param pkey 服务端密钥句柄
 * @param e 待签名消息杂凑值
 * @param elen 待签名消息杂凑值长度
 * @param Q1 客户端Q1
 * @param q1len 客户端Q1长度
 * @param r 服务端输出r,外部传入buffer, （大于等于32字节)
 * @param rsize 传入r buffer大小
 * @param rlen 传出r实际长度
 * @param s2 服务端输出s2,外部传入buffer, （大于等于32字节)
 * @param s2size 传入s2 buffer大小
 * @param s2len 传出r实际长度
 * @param s3 服务端输出s3,外部传入buffer, （大于等于32字节)
 * @param s3size 传入s3 buffer大小
 * @param s3len 传出s3实际长度
 *
 * @return 0成功，非0失败
 */
int libmbedsm2_server_ecp_ecdsa_sign( MBEDSM2_PKEY_CTX pkey, 
		const unsigned char *e, size_t elen,
		const unsigned char *Q1, size_t q1len,
		unsigned char *r, size_t rsize, size_t *rlen,
		unsigned char *s2, size_t s2size, size_t *s2len,
		unsigned char *s3, size_t s3size, size_t *s3len
		);

/**
 * @brief 客户端端签名(step two)
 * 
 * @param ctx 客户端签名ctx
 * @param pkey 客户端密钥句柄
 * @param r 服务端输出的r参数
 * @param rlen 服务端输出r参数的长度
 * @param s2 服务端输出的s2参数
 * @param s2len 服务端输出s2参数的长度
 * @param s3 服务端输出的s3参数
 * @param s3len 服务端输出s3参数的长度
 * @param out 输出签名值，外部传入buffer, （大于等于75字节）
 * @param osize 输出签名值buffer长度
 * @param olen 返回签名值实际长度
 *
 * @note 输出DER编码签名
 * @return 0成功， 非0失败
 */
int libmbedsm2_client_ecp_ecdsa_sign_step_two( MBEDSM2_ECDSA_CONTEXT ctx, 
		MBEDSM2_PKEY_CTX pkey, 
		const unsigned char *r, size_t rlen,
		const unsigned char *s2, size_t s2len,
		const unsigned char *s3, size_t s3len,
		unsigned char *out, size_t osize, size_t *olen
		);

/**
 * @brief 客户端端签名解析（r,s)值
 *
 * @param sig 签名值
 * @param slen 签名值长度
 * @param r 外部输入r buffer (大于等于32字节)
 * @param rsize 外部输入r buffer长度
 * @param rlen 输出r实际长度
 * @param s 外部输入s buffer(大于等于32字节)
 * @param ssize 外部输入s buffer长度
 * @param slen 输入s实际长度
 * 
 * @return 0 成功，非0失败
 */
int libmbedsm2_client_ecp_ecdsa_export_rs(const unsigned char *sig,
		size_t siglen,
		unsigned char *r, size_t rsize, size_t *rlen,
		unsigned char *s, size_t ssize, size_t *slen);

/**
 * @brief 验证签名
 *
 * @param pkey 密钥句柄
 * @param input 待验证数据
 * @param ilen 待验证数据长度
 * @param sig 签名值
 * @param slen 签名值长度
 *
 * @return 0 成功，非0失败
 */
int libmbedsm2_ecp_ecdsa_verify( MBEDSM2_PKEY_CTX pkey,
		const unsigned char *input, size_t ilen, 
		const unsigned char *sig, size_t slen);

/**
 * @brief 验证摘要签名
 * 
 * @param pkey 密钥句柄
 * @param hash 杂凑值
 * @param hlen 杂凑值长度
 * @param sig 签名值
 * @param slen 签名值长度
 *
 * @return 0 成功，非 0失败
 */
int libmbedsm2_ecp_ecdsa_digest_verify( MBEDSM2_PKEY_CTX pkey,
		const unsigned char *hash, size_t hlen,
		const unsigned char *sig, size_t slen );

/**
 * @brief 释放签名句柄
 * 
 * @param ctx 签名句柄
 */
void libmbedsm2_ecdsa_free(MBEDSM2_ECDSA_CONTEXT ctx);

/**
 *  Decrypt 
 *  Client ===================================== Server
 *  ---------------T1(Point) -------------------->
 *  <--------------rT2(Point) --------------------
 *  Compute signature
 */

/**
 * @brief 公钥加密
 * 
 * @param pkey 密钥句柄
 * @param m 待加密消息
 * @param mlen 待加密消息长度
 * @param c 输出加密密文, buffer （长度应大于 m长度+120字节）
 * @param csize buffer 长度 
 * @param clen 输出实际密文长度
 *
 * @note 输出DER编码的密文
 * @return 0 成功， 非0 失败
 */
int libmbedsm2_ecp_ecies_encrypt( MBEDSM2_PKEY_CTX pkey,
		const unsigned char *m, size_t mlen,
		unsigned char *c, size_t csize, size_t *clen);

/**
 * @brief 客户端私钥解密（step one)
 *
 * @param pkey 客户端密钥句柄
 * @param c 密文
 * @param clen 密文长度
 * @param t1 输出t1点,外部传入buffer (长度应大于等于67字节)
 * @param t1size t1 buffer长度
 * @param t1len 输出实际t1len长度
 *
 * @return 0 成功，非0失败
 */
int libmbedsm2_client_ecp_ecies_decrypt_step_one( MBEDSM2_PKEY_CTX pkey, 
		const unsigned char *c ,size_t clen,
		unsigned char *t1, size_t t1size, size_t *t1len);

/**
 * @brief 服务端私钥解密
 *
 * @param pkey 服务端密钥句柄
 * @param t1 客户端t1点
 * @param t1len 客户端t1长度
 * @param t2 t2点，外部传入buffer, （长度大于等于67字节)
 * @param t2size t2大小
 * @param t2len 传出t2实际大小
 *
 * @return 0成功，非0失败
 */
int libmbedsm2_server_ecp_ecies_decrypt( MBEDSM2_PKEY_CTX pkey, 
		const unsigned char *t1, size_t t1len,
		unsigned char *t2, size_t t2size, size_t *t2len);

/**
 * @brief 客户端私钥解密 （step two)
 *
 * @param pkey 客户端密钥句柄
 * @param c 密文
 * @param clen 密文长度
 * @param t2 服务端t2点
 * @param t2len 服务端t2 长度
 * @param m 明文，外部传入，长度必须大于密文-96字节
 * @param msize 明文长度
 * @param mlen 输出明文实际大小
 * 
 * @return 0成功，非0失败
 */ 
int libmbedsm2_client_ecp_ecies_decrypt_step_two( MBEDSM2_PKEY_CTX pkey, 
		const unsigned char *c ,size_t clen,
		const unsigned char *t2, size_t t2len,
		unsigned char *m, size_t msize, size_t *mlen);

/**
 * @brief 回调随机数函数(用户实现)
 * @param p_arg 为用户数据，如果不用，设置为NULL
 * @param buf 已分配buffer
 * @param bsize buffer长度
 */
typedef int (*libmbedsm2_rnd_func_ptr)(void *p_arg, unsigned char *buf, size_t bsize);

/**
 * @brief 设置全局随机数获取函数
 * @param p_func 回调函数指针
 * @param p_arg 回调函数参数
 * @return 0成功， 非0失败
 */
int libmbedsm2_rnd_set_global_func(libmbedsm2_rnd_func_ptr p_func, void *p_arg);

#define MBEDSM2_OK            0                  /**< CYSEC_RET返回值: 成功 */

#define MBEDSM2_E_BASE        0x00010000          /**< CYSEC_RET错误码掩码 */
#define MBEDSM2_E_UNSUPPORTED (MBEDSM2_E_BASE + 1)  /**< 当前操作尚未支持 */
#define MBEDSM2_E_INVALID_ARG (MBEDSM2_E_BASE + 2)  /**< 输入的参数有错误 */
#define MBEDSM2_E_INVALID_SIG (MBEDSM2_E_BASE + 3)  /**< 非法签名 */
#define MBEDSM2_E_MEMORY_E    (MBEDSM2_E_BASE + 4)  /** 内存分配失败 */
#define MBEDSM2_E_SMALL_BUFFER (MBEDSM2_E_BASE + 5) /** 传入内存太小 */

#define MBEDSM2_E_ECDSA_BASE 0x00010100
#define MBEDSM2_E_ECDSA_S_IS_ZERO (MBEDSM2_E_ECDSA_BASE + 1) /* s==0 */
#define MBEDSM2_E_ECDSA_S_EQUAL_N_MINUS_R (MBEDSM2_E_ECDSA_BASE + 2) /* s == n-r */

#define MBEDSM2_E_ECIES_BASE	0x00010200
#define MBEDSM2_E_ECIES_KDF_ERROR	(MBEDSM2_E_ECIES_BASE +1) /* MBEDSM2_E_BASE + 0x102*/
#define MBEDSM2_E_ECIES_U_C3_NO_MATCH (MBEDSM2_E_ECIES_BASE + 3)

#define MBEDSM2_E_RAND_BASE 		0x00010300
#define MBEDSM2_E_RAND_THREAD_LOCK_ERROR  (MBEDSM2_E_RAND_BASE + 1)
#define MBEDSM2_E_RAND_THREAD_UNLOCK_ERROR (MBEDSM2_E_RAND_BASE + 2)
#define MBEDSM2_E_RAND_OPEN_ERROR	(MBEDSM2_E_RAND_BASE + 3)
#define MBEDSM2_E_RAND_BLOCK_ERROR (MBEDSM2_E_RAND_BASE + 4)
#define MBEDSM2_E_RAND_READ_ERROR (MBEDSM2_E_RAND_BASE + 5)

#ifdef __cplusplus
}
#endif

#endif /* __LIB_MBED_SM2_H */