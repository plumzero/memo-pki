/**
 *	Purpose: 	实现国标SM3/SCH摘要算法
 *	Version：	1.2
 *	Update:		2010-12-23 created by 掌晓愚
 *	Update:		2011-03-22 update according to 曾萌
 *	Update:		2011-05-05 rewrite by 掌晓愚
 *
 *	具体的算法规范文档可以从国密的网站上下载：
 *	http://www.oscca.gov.cn/Doc/2/News_1199.htm
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "sm3.h"

//#define SM3_DEBUG

/***************************************************************************************
 *
 *	第0部分: 
 *	调试用的工具函数
 *
 ***************************************************************************************/

#ifdef SM3_DEBUG
static void sm3_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}

void sm3_dump(const char *desc, const unsigned char *data, int data_cb)
{
	return;
	{
   		int i = 0;
   		char line[128] = {0};

		if (desc) {
			sm3_debug("%s[%p/%d]\n", desc, data, data_cb);
		}
		else  {
			sm3_debug("data[%p/%d]\n", data, data_cb);
		}
	    
		for (i =0; i<data_cb; i++) {
			if ( i>0 && i%32 == 0 ) {
				sm3_debug("%s\n", line);
				line[0] = 0;
			}

			_snprintf(line + (i%32) * 3, 4, "%02X ", *(data+i));
		}
		
		sm3_debug("%s\n\n", line);
	}
}
#else
static void sm3_debug(const char *format, ...){}
void sm3_dump(const char *desc, const unsigned char *data, int data_cb) {}
#endif /* SM3_DEBUG */


/***************************************************************************************
 *
 *	第1部分: 
 *	根据《SM3密码杂凑算法》实现各章节定义的算法逻辑
 *
 *	!!!! 注意，根据规范，下面代码中的“字”为32位（4字节），而不是通常x86架构含义中的16位（2字节）
 *
 ***************************************************************************************/

/*	Win32环境下默认为小端，linux环境下在c库中已有定义	*/
#ifdef WIN32
#define __LITTLE_ENDIAN
#endif /* WIN32 */

/*	4.1 初始值			*/
static sm3_word_t SM3_IV[8] = {	0x7380166f, \
								0x4914b2b9, \
								0x172442d7, \
								0xda8a0600, \
								0xa96f30bc, \
								0x163138aa, \
								0xe38dee4d, \
								0xb0fb0e4e  };

/*	4.2 常量			*/
#define T(j)			((j >= 0 && j <= 15) ? 0x79cc4519 :((j >= 16 && j <= 63) ? 0x7a879d8a : 0))

/*	4.3 布尔函数子函数	*/
#define FG(x,y,z)		(x ^ y ^ z)
#define F1(x,y,z)		((x & y) | (y & z) | (x & z))
#define G1(x,y,z)		((x & y) | (~x & z))

#define FF(j,x,y,z)		((j >= 0 && j <= 15) ? FG(x,y,z) :((j >= 16 && j <= 63) ? F1(x,y,z) : 0))

#define GG(j,x,y,z)		((j >= 0 && j <= 15) ? FG(x,y,z) :((j >= 16 && j <= 63) ? G1(x,y,z) : 0))

/*	4.4 置换函数P0		*/
#define P0(x)			(x ^ (sm3_lshift(x,9))  ^ (sm3_lshift(x,17)))
#define P1(x)			(x ^ (sm3_lshift(x,15)) ^ (sm3_lshift(x,23)))




/*	针对单字的循环左移	*/
static sm3_word_t sm3_lshift(sm3_word_t num, unsigned int bits)
{
	return (num >> (32 - bits) | (num << bits));
}

/*	针对单字的大小端转换	*/
static sm3_word_t sm3_rot(sm3_word_t num)
{
#ifdef __LITTLE_ENDIAN
	int i = 0;
	sm3_word_t num_b = 0;

	unsigned char *ln = (unsigned char *)(&num);
	unsigned char *bn = (unsigned char *)(&num_b);

	for (i = 0; i < 4; i++)
	{
		bn[i] = ln[3-i];
	}

	return num_b;
#else
	return num;
#endif /* __LITTLE_ENDIAN */
}

/*	针对字数组的大小端转换	*/
static void sm3_rot_r(const sm3_word_t* in, unsigned int count, sm3_word_t* out)
{
#ifdef __LITTLE_ENDIAN
	unsigned int i = 0;
	for (i = 0; i < count; i++) {
		out[i] = sm3_rot(in[i]);
	}
#else
	memcpy(out, in, count * sizeof(sm3_word_t));
#endif /* __LITTLE_ENDIAN */
}

/**
 *	5.2 填充
 *	
 *	假设消息m的长度为mbits比特。首先将比特1添加到消息的末尾，再添加k个0，
 *	k是满足mbits + 1 + k = 448mod512 的最小的非负整数。
 *	然后再添加一个64位比特串，该比特串是长度mbits的二进制表示。
 *	填充后的消息m'的比特长度为512的倍数。
 *
 *	例1：对消息01100001 01100010 01100011，其长度mbits=24，k=448-1-24=443，经填充得到比特串：
 *	                             {423比特0}  {64比特}
 *	01100001 01100010 01100011 1 00......00  00 ... 000011000
 *	                                         {24的二进制表示}
 *
 *	例2：对消息01100001 01100010 01100011，其长度mbits=440，k=448-1-440=7，经填充得到比特串：
 *	                             {7比特0}    {64比特}
 *	01100001 01100010 01100011 1 00......00  00 ... 110111000
 *	                                         {440的二进制表示}
 *
 *	例2：对消息00000000 ........ 00000000，其长度mbits=504，k=512+448-1-504=455，经填充得到比特串：
 *	                             {455比特0}  {64比特}
 *	00000000 ........ 00000000 1 00......00  00 ... 111111000
 *	                                         {504的二进制表示}
 */
 
static unsigned int sm3_padding(unsigned int m_bytes, unsigned char* out)
{
	unsigned int k = 0;
	unsigned int m_bits = m_bytes * 8;
	unsigned int mod_bits = m_bits % 512;
	unsigned char *p = NULL;
	
	/*	计算填充k长度：k = 448mod512 - 1 - mod_bits，且因为m_bits为8的整数倍，因此k不会为0	*/
	if (mod_bits <= 447) {
		k = 447 - mod_bits;
	}
	else  {
		k = 512 + 447 - mod_bits;
	}
	
	/*	如果未指定输出，则只计算长度（字节）并返回	*/
	if (NULL == out) {
		return (m_bits + 1 + k + 64)/8;
	}

	p = out;

	/*	因为我们处理的m_bits都是8的倍数，所以这里直接用0x80代替比特1进行填充	*/
	*p = 0x80;
	p++;

	/*	再补充(k/8)字节0		*/
	if ( (k/8) > 0 ) {
		memset(p, 0, k/8);
		p += k/8;
	}

	/*	再补充8字节(64比特)长度，在m_bytes为32位情况下，前4字节固定为0	*/
	memset(p, 0, 4);
	p += 4;

	*p++ = (unsigned char)((m_bits & 0xFF000000) >> 24);
	*p++ = (unsigned char)((m_bits & 0x00FF0000) >> 16);
	*p++ = (unsigned char)((m_bits & 0x0000FF00) >> 8);
	*p++ = (unsigned char)((m_bits & 0x000000FF));

	sm3_dump("sm3_padding: padding of m", out, p - out);

	/*	返回填充后的消息长度（字节），此值应该是64字节(512比特)的整数倍	*/
	return p - out;
}

/**
 *	5.3.2 消息扩展
 *
 *	将消息分组B(i)按以下方法扩展生成132个字W0, W1, ...W67, W′0, W′1, ...W′63
 *	a)	将消息分组B(i)划分为16个字W0, W1, ...W15
 *	b)	FOR j=16 TO 67
 *			Wj = P1(Wj-16 ⊕ Wj-9 ⊕ (Wj-3 <<< 15)) ⊕ (Wj-13 <<< 7) ⊕ Wj-6
 *		ENDFOR
 *	c)	FOR j=0 TO 63
 *			W′j = Wj ⊕ Wj+4
 *		ENDFOR
 *	
 *	注1：⊕  表示32比特异或运算
 *	     <<< 表示循环左移k比特运算
 */
static void sm3_extend(const unsigned char *b, sm3_word_t *w)
{
	unsigned int i = 0;
	unsigned int j = 0;

	sm3_dump("sm3_extend: b", b, 64);
	
	/*	b的长度应该固定为16个字，也即64字节	*/
	sm3_rot_r((const sm3_word_t *)b, 16, w);
	
	for (i = 16; i < 68; i++) {
		w[i] = P1((w[i - 16]) ^ (w[i - 9]) ^ (sm3_lshift(w[i - 3],15))) ^ (sm3_lshift(w[i - 13],7))  ^ w[i - 6];
	}

 	for (j = 0; j < 64; j++)
 	{
 		w[68 + j] = w[j] ^ w[j + 4];
 	}

	sm3_dump("sm3_extend: w", (const unsigned char *)w, 68 * sizeof(sm3_word_t));
	sm3_dump("sm3_extend: w'", (const unsigned char *)(w + 68), 64 * sizeof(sm3_word_t));
}

/**
 *	5.3.2 压缩函数
 *	令A,B,C,D,E,F,G,H为字寄存器, SS1,SS2,TT1,TT2为中间变量,
 *	压缩函数V(i+1) = CF(V(i),B(i)), 0 <= i <= n-1。
 *
 *	计算过程描述如下：
 *	ABCDEFGH = V(i)
 *	FOR j=0 TO 63
 *		SS1 = ((A <<< 12) + E + (Tj <<< j)) <<< 7
 *		SS2 = SS1 ⊕ (A <<< 12)
 *		TT1 = FFj(A,B,C) + D + SS2 +W′j
 *		TT2 = GGj(E,F,G) + H + SS1 +Wj
 *		D = C
 *		C = B <<< 9
 *		B = A
 *		A = TT1
 *		H = G
 *		G = F <<< 19
 *		F = E
 *		E = P0(TT2)
 *	ENDFOR
 *	
 *	V(i+1) = ABCDEFGH ⊕ V(i)
 *
 *	注1：⊕  表示32比特异或运算
 *	     <<< 表示循环左移k比特运算
 *	注2：字的存储为大端(big-endian)格式。
 */
static void sm3_compress(sm3_word_t *v, sm3_word_t *w)
{
	/*	v和vi都固定为8个字，也即32字节	*/
	sm3_word_t vi[8] = {0};
	sm3_word_t *A = vi;
	sm3_word_t *B = vi+1;
	sm3_word_t *C = vi+2;
	sm3_word_t *D = vi+3;
	sm3_word_t *E = vi+4;
	sm3_word_t *F = vi+5;
	sm3_word_t *G = vi+6;
	sm3_word_t *H = vi+7;
	
	sm3_word_t SS1 = 0;
	sm3_word_t SS2 = 0;
	sm3_word_t TT1 = 0;
	sm3_word_t TT2 = 0;

	unsigned int j = 0;
	
	/*	ABCDEFGH = V(i)	*/
	memcpy(vi, v, sizeof(vi));

	sm3_dump("sm3_compress: v(i)", (const unsigned char *)v, 32);
	
	for (j = 0; j <= 63; j++) {
		/*		SS1 = ((A <<< 12) + E + (Tj <<< j)) <<< 7	*/
		SS1 = sm3_lshift(sm3_lshift(*A, 12) + (*E) + sm3_lshift(T(j), j), 7);
		
		/*		SS2 = SS1 ⊕ (A <<< 12)						*/
		SS2 = SS1 ^ sm3_lshift(*A, 12);
		
		/*		TT1 = FFj(A,B,C) + D + SS2 +W′j			*/
		TT1 = FF(j, *A, *B, *C) + (*D) + SS2 + w[68+j];

		/*		TT2 = GGj(E,F,G) + H + SS1 +Wj				*/
		TT2 = GG(j, *E, *F, *G) + (*H) + SS1 + w[j];
		
		/*		D = C										*/
		*D = *C;
		
		/*		C = B <<< 9									*/
		*C = sm3_lshift(*B, 9);

		/*		B = A										*/
		*B = *A;
		
		/*		A = TT1										*/
		*A = TT1;
		
		/*		H = G										*/
		*H = *G;
		
		/*		G = F <<< 19								*/
		*G = sm3_lshift(*F, 19);
		
		/*		F = E										*/
		*F = *E;

		/*		E = P0(TT2)									*/
		*E = P0(TT2);
	}

	/*	V(i+1) = ABCDEFGH ⊕ V(i)	*/
	for (j = 0; j < 8; j++) {
		v[j] = v[j] ^ vi[j];
	}

	sm3_dump("sm3_compress: v(i+1)", (const unsigned char *)v, 32);
}


/**
 *	5.3.1 迭代过程
 *	将填充后的消息m′按64字节（512比特）进行分组：m′ = B(0)B(1)...B(n-1)
 *	其中n=m_size/512。
 *	对m′按下列方式迭代：
 *
 *	FOR i=0 TO n-1
 *		V(i+1) = CF(V(i), B(i))
 *	ENDFOR
 *
 *	其中CF是压缩函数，V(0)为256比特初始值IV，B(i)为填充后的消息分组，迭代压缩的结果为V(n)。 
 */
static unsigned int sm3_loop(const unsigned char *m, unsigned int m_bytes, sm3_word_t *iv)
{
	unsigned int left_bytes = m_bytes;
	const unsigned char *b = m;
	unsigned int i = 0;
	
	/*	填充后的消息分组(132个字)	*/
	sm3_word_t w[132] = {0};

	while (left_bytes > 0) {

		if (left_bytes < 64) {
			/*	这种情况不应该出现	*/
			sm3_debug("invalid size: m_bytes=%d, left_bytes=%d\n", m_bytes, left_bytes);
			return 0;
		}

		sm3_extend(b, w);

		sm3_compress(iv, w);
	
		left_bytes -= 64;
		b += 64;
		
		i++;
	}	

	/*	返回迭代次数	*/
	return i;
}



/***************************************************************************************
 *
 *	第2部分: 
 *	将算法原子操作封装为3段式(init/update/final)的调用函数
 *
 ***************************************************************************************/

int sm3_init(SM3_CTX *ctx)
{
	memset(ctx, 0, sizeof(SM3_CTX));

	memcpy(ctx->iv, SM3_IV, sizeof(ctx->iv));

	return 1;
}

int sm3_update(SM3_CTX *ctx, const unsigned char *m, unsigned int m_bytes)
{
	unsigned int pm_len = 0;
	const unsigned char *pm = NULL;

	/*	记录数据长度，留待计算最后的padding	*/
	ctx->m_size += m_bytes;

	if ( ctx->r_len && (ctx->r_len + m_bytes) >= 64 ) {

		/*	如果存在剩余数据，且可以和新数据组成一个新的块，则进行拼接并处理	*/
		memcpy(ctx->remain + ctx->r_len, m, 64 - ctx->r_len);
		sm3_loop(ctx->remain, 64, ctx->iv);

		/*	移动m的指针，并递减m_bytes		*/
		m += (64 - ctx->r_len);
		m_bytes -= (64 - ctx->r_len);

		/*	剩余数据清0						*/
		memset(ctx->remain, 0, sizeof(ctx->remain));
		ctx->r_len = 0;
	}
	
	if (ctx->r_len) {

		/*	剩余数据和新数据仍然不足以组成一个新的块，只能将新数据继续保存到remain中	*/
		memcpy(ctx->remain + ctx->r_len, m, m_bytes);
		ctx->r_len += m_bytes;
	}
	else {

		/*	只处理对齐到块长度的数据，其他的保留到ctx->remain中留待后续处理	*/
		pm = m;
		pm_len = m_bytes - (m_bytes % 64);
			
		if (pm_len) {
			sm3_loop(pm, pm_len, ctx->iv);
		}

		/*	保存剩余数据到remain中	*/
		if (m_bytes > pm_len) {
			memcpy(ctx->remain, pm + pm_len, (m_bytes - pm_len));
			ctx->r_len = (m_bytes - pm_len);
		}
	}

	return 1;
}

int sm3_final(SM3_CTX *ctx, unsigned char *dgst)
{
	unsigned int pm_len = 0;
	
	pm_len = sm3_padding(ctx->m_size, ctx->remain + ctx->r_len);
	pm_len += ctx->r_len;

	sm3_loop(ctx->remain, pm_len, ctx->iv);

	sm3_rot_r(ctx->iv, 8, (sm3_word_t*)dgst);

	sm3_dump("sm3_final: dgst", dgst, sizeof(ctx->iv));

	return sizeof(ctx->iv);
}

int sm3_hash_simple(const unsigned char *m, int m_bytes, unsigned char *dgst)
{
	unsigned char *pm = NULL;
	unsigned int pm_len = 0;
	sm3_word_t iv[8] = {0};

	/*	padding	*/
	pm_len = sm3_padding(m_bytes, NULL);
	pm = (unsigned char *)calloc(m_bytes + pm_len, 1);

	memcpy(pm, m, m_bytes);
	sm3_padding(m_bytes, pm + m_bytes);

	/*	loop	*/
	memcpy(iv, SM3_IV, sizeof(iv));
	sm3_loop(pm, pm_len, iv);

	/*	output	*/
	sm3_rot_r(iv, 8, (sm3_word_t*)dgst);
	sm3_dump("sm3_hash_simple: dgst", dgst, 32);

	if (pm) {
		free(pm);
		pm = NULL;
	}

	return 0;
}

int sm3_hash(const unsigned char* pBuffer, unsigned uLen, unsigned char *dgst)
{
	unsigned char dgst2[32] = {0};

	sm3_dump("buffer", pBuffer, uLen);

	/**
	 *	dgst2 must be:
	 *	debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732
	 */
	if (1) {
		sm3_hash_simple(pBuffer, uLen, dgst2);
	}
	else {
		//*	三段式调用，并人为地将输入数据拆分为3部分	*/
		SM3_CTX ctx = {0};
		sm3_init(&ctx);

		sm3_update(&ctx, pBuffer, 31);
		sm3_update(&ctx, pBuffer + 31, 3);
		sm3_update(&ctx, pBuffer + 31 + 3, uLen - 31 - 3);

		sm3_final(&ctx, dgst2);

		///*	三段式调用，并人为地将输入数据拆分为2部分	*/
		//SM3_CTX ctx = {0};
		//sm3_init(&ctx);

		//sm3_update(&ctx, pBuffer, 68);
		//sm3_update(&ctx, pBuffer + 68, uLen - 68);

		//sm3_final(&ctx, dgst2);


	}
	memcpy(dgst, dgst2, 32);

	sm3_dump("dgst:", dgst, 32);

	return 1;
}

int sm3(const unsigned char* pBuffer, unsigned uLen, unsigned char *dgst)
{
	return sm3_hash(pBuffer, uLen, dgst);
}