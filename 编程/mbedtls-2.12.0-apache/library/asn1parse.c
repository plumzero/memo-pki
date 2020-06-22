/*
 *  Generic ASN.1 parsing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)

#include "mbedtls/asn1.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/*
 * ASN.1 DER decoding routines
 */
 /**
	长度串编码分为短型和长型两种方式
	1. 短型长度串编码
	   ① 适用于内容长度小于 127 的类型；
	   ② 编码只有一个字节；
	   ③ 第 8 位置为 0，其他 7 位填充长度的值（是内容串的长度）
	2. 长型长度串编码
	   ① 适用于内容长度大于 127 的类型；
	   ② 编码由 2~127 个字节组成；
	   ③ 第 1 个字节的第 8 位置为 1，其他 7 位填充后面填充长度值所有的字节数；
	   ④ 第 2 个字节以后（包含第 2 个字节）的字节，填充内容串的长度值
 
	短型长度串编码示例：
		+--------+--------+--------+--...--+--------+----
		|  tag   | length | value  |       | value  | val
		| 八位组 | 八位组 | 八位组 |       | 八位组 | 八位
		+--------+--------+--------+--...--+--------+----
	长型长度串编码示例：
		+--------+--------+--------+--...--+--------+--------+--------+----
		|  tag   | length |   len  |       |   len  |  value | value  | val
		| 八位组 | 八位组 | 八位组 |       | 八位组 | 八位组 | 八位组 | 八位
		+--------+--------+--------+--...--+--------+--------+--------+----		
  */
int mbedtls_asn1_get_len( unsigned char **p,
                  const unsigned char *end,
                  size_t *len )
{
    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( ( **p & 0x80 ) == 0 )			// 短型长度串编码
        *len = *(*p)++;					// 内容串长度
    else		// 长型长度串编码
    {
        switch( **p & 0x7F )
        {
        case 1:
            if( ( end - *p ) < 2 )
                return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );

            *len = (*p)[1];		// 内容串长度
            (*p) += 2;			// 指向内容串首字节
            break;

        case 2:
            if( ( end - *p ) < 3 )
                return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );

            *len = ( (size_t)(*p)[1] << 8 ) | (*p)[2];
            (*p) += 3;
            break;

        case 3:
            if( ( end - *p ) < 4 )
                return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );

            *len = ( (size_t)(*p)[1] << 16 ) |
                   ( (size_t)(*p)[2] << 8  ) | (*p)[3];
            (*p) += 4;
            break;

        case 4:			// 不必太长，一个整数足矣
            if( ( end - *p ) < 5 )
                return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );

            *len = ( (size_t)(*p)[1] << 24 ) | ( (size_t)(*p)[2] << 16 ) |		// 大端存储
                   ( (size_t)(*p)[3] << 8  ) |           (*p)[4];
            (*p) += 5;
            break;

        default:
            return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );
        }
    }

    if( *len > (size_t) ( end - *p ) )			// 确定 *len 与内容串真实长度相等
        return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    return( 0 );
}
/**
	标识串编码分为低标识编码和高标识编码两种形式。
	1. 低标识编码
	   ① 适用于类型标识值小于 30 的类型；
	   ② 编码结果只有 1 个字节；
	   ③ 其中第 8 位和第 7 位表示 Class 类型，其赋值规则如下：
			+------------------+----------+----------++------------------+----------+----------+
			|       Class      |  第 8 位 |  第 7 位 ||       Class      |  第 8 位 |  第 7 位 |
			+------------------+----------+----------++------------------+----------+----------+
			|     Universal    |    0     |     0    || Context-Specific |     1    |     0    |
			+------------------+----------+----------++------------------+----------+----------+
			|    Application   |    0     |     1    ||       Private    |     1    |     1    |
			+------------------+----------+----------++------------------+----------+----------+
		④ 第 6 位置为 0 表示是基本类型的编码；
		⑤ 第 5 位到第 1 位填充数据类型标识的值
	2. 高标识编码
	   ① 适用于类型标识值大于 30 的类型；
	   ② 编码结果至少有 2 个字节；
	   ③ 除了将第 5 到第 1 位置为 1，第一个字节与低醣编码获得的标识串的构成相同；
	   ④ 将第 2 个字节以后（包含第 2 个字节）的字节填充类型标识的值，基数是 128，每个字节的第 8 位作
	      为结束标志，除了最后一个字节外其他都置为 1
 */
int mbedtls_asn1_get_tag( unsigned char **p,
                  const unsigned char *end,
                  size_t *len, int tag )	
{
    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( **p != tag )			// 编码的标识串与传入的标识比较
        return( MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;						// 指向长度串

    return( mbedtls_asn1_get_len( p, end, len ) );	// p 指向内容串，len 填充内容串长度
}

/** 以下都是对内容串的获取，类型定义见 asn1.h */
/**
	BOOLEAN 类型通用类：
		标识：			0x01
		mbedtls 标识：	MBEDTLS_ASN1_BOOLEAN
		长度：			1						DER 采用最短编码规则，BOOLEAN 只用 1 个字节存储
 */
int mbedtls_asn1_get_bool( unsigned char **p,
                   const unsigned char *end,
                   int *val )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_BOOLEAN ) ) != 0 )
        return( ret );

    if( len != 1 )
        return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );

    *val = ( **p != 0 ) ? 1 : 0;		// 内容串值
    (*p)++;								// 指向下一个 tlv

    return( 0 );
}
/**
	INTEGER 类型通用类：
		标识：			0x02
		mbedtls 标识：	MBEDTLS_ASN1_INTEGER
		内容串长度：	1 ~ 4
 */
int mbedtls_asn1_get_int( unsigned char **p,
                  const unsigned char *end,
                  int *val )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ) ) != 0 )
        return( ret );

	/**
		对于 INTEGER 类型，DER 编码后内容串第 1 个字节第 8 位表示正负整数，因此如果正整数
		第 1 字节第 8 位为 1 时，在前填充 1 个字节 0x00。如 0x80，编码后为 00 80。
		
		mbedtls 不支持对负 INTEGER 的解析，所以内容串中不需要填充 0x00
	 */
    if( len == 0 || len > sizeof( int ) || ( **p & 0x80 ) != 0 )
        return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );

    *val = 0;

    while( len-- > 0 )
    {
        *val = ( *val << 8 ) | **p;
        (*p)++;
    }

    return( 0 );
}

#if defined(MBEDTLS_BIGNUM_C)
int mbedtls_asn1_get_mpi( unsigned char **p,
                  const unsigned char *end,
                  mbedtls_mpi *X )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_INTEGER ) ) != 0 )
        return( ret );

    ret = mbedtls_mpi_read_binary( X, *p, len );

    *p += len;

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C */
/**
	BIT STRING 类型通用类：
		标识：			0x03
		mbedtls 标识：	MBEDTLS_ASN1_BIT_STRING
		长度：			1 ~ 4
	BIT STRING 编码格式：
	+--------+--------+-----------+-----------+-----------+----
	|  tag   | length | value for | value for | value for | 
	| octet  | octet  |unused bits| bit string| bit string| ...
	+--------+--------+-----------+-----------+-----------+---
	BIT STRING的 tlv 中的 value 中，第 1 位存储 unused bits 的数量，确保不超过 7
	因为 value 的第 1 位要存储 unused bits ，所以 value 至少占用 1 个八位组
	
	length octet = 1 + 真正的内容串长度
	如果 BIT STRING 为空，则 value for unused bits 值为 0
 */
int mbedtls_asn1_get_bitstring( unsigned char **p, const unsigned char *end,
                        mbedtls_asn1_bitstring *bs)
{
    int ret;

    /* Certificate type is a single byte bitstring */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &bs->len, MBEDTLS_ASN1_BIT_STRING ) ) != 0 )
        return( ret );

    /* Check length, subtract one for actual bit string length */
    if( bs->len < 1 )			// 内容串至少占一个八位组
        return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );
    bs->len -= 1;

    /* Get number of unused bits, ensure unused bits <= 7 */
    bs->unused_bits = **p;	
    if( bs->unused_bits > 7 )
        return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );
    (*p)++;						// 指向真正的内容串

    /* Get actual bitstring */
    bs->p = *p;
    *p += bs->len;				// bs->len 是真正内容串的长度

    if( *p != end )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * Get a bit string without unused bits
 */
/**
	大概是这样的：
	+--------+--------+-----------+-----------+-----------+----
	|  tag   | length |  sub tag  | sub len   | sub value | 
	| octet  | octet  |   octet   |   octet   |   octet   | ...
	+--------+--------+-----------+-----------+-----------+----
	                  |<-         content octets            ->|
	|<-                     BIT STRING                      ->|
	
 */
int mbedtls_asn1_get_bitstring_null( unsigned char **p, const unsigned char *end,
                             size_t *len )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_tag( p, end, len, MBEDTLS_ASN1_BIT_STRING ) ) != 0 )
        return( ret );

    if( (*len)-- < 2 || *(*p)++ != 0 )
        return( MBEDTLS_ERR_ASN1_INVALID_DATA );

    return( 0 );
}



/*
 *  Parses and splits an ASN.1 "SEQUENCE OF <tag>"
 */
 /**
	一般结构类型的解析：
 	以一个ASN.1作为例子
		FooQuestion ::= SEQUENCE{
			trackingNumber		INTEGER(0.199),
			question			IA5String
		}
	PDU
		myQuestion FooQuestion ::= {
			trackNumber		5,
			question		"Anybody there?"
		}
	使用UNIVERSAL标签类型，对上述 SEQUENCE OF 进行编码(hexadecimal)：
		+-----+------+-----+------+-----+-----+------+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
		| tag |length| tag |length|value|tag  |length|value|value|value|value|value|value|value|value|value|value|value|value|value|value|
		|octet|octet |octet|octet |octet|octet|octet |octet|octet|octet|octet|octet|octet|octet|octet|octet|octet|octet|octet|octet|octet|
		+-----+------+-----+------+-----+-----+------+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
		|10/20|  13  | 02  |  01  | 05  | 16  |  0e  |  41 |  6e |  79 |  62 |  6f |  64 | 79  |  20 |  74 |  68 | 65  |  72 |  65 |  3f |
		+-----+------+-----+------+-----+-----+------+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
									5				   'A'	 'n'   'y'   'b'   'o'   'd'   'y'   ' '   't'   'h'   'e'   'r'   'e'   '?'		
	层级：
		FooQuestion			// 1 级
			trackNumber		// 2 级
			question		// 2 级
  */	
int mbedtls_asn1_get_sequence_of( unsigned char **p,
                          const unsigned char *end,
                          mbedtls_asn1_sequence *cur,		// 指向链表的第一个节点
                          int tag)
{
    int ret;
    size_t len;
    mbedtls_asn1_buf *buf;

    /* Get main sequence tag */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )		// mbedtls规定，MBEDTLS_ASN1_CONSTRUCTED 与 MBEDTLS_ASN1_SEQUENCE 同类
        return( ret );

    if( *p + len != end )		// 内容串长度校验
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    while( *p < end )	// 大循环
    {
        buf = &(cur->buf);
        buf->tag = **p;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &buf->len, tag ) ) != 0 )
            return( ret );

        buf->p = *p;
        *p += buf->len;		// 下一个 mbedtls_asn1_sequence 链表节点的 tlv

        /* Allocate and assign next pointer */
        if( *p < end )		// mbedtls_asn1_sequence 中的 tlv 是同级的。为扩展的需要，第 1 个节点之后的 mbedtls_asn1_buf 在堆中分配内存
        {
            cur->next = (mbedtls_asn1_sequence*)mbedtls_calloc( 1,
                                            sizeof( mbedtls_asn1_sequence ) );

            if( cur->next == NULL )
                return( MBEDTLS_ERR_ASN1_ALLOC_FAILED );

            cur = cur->next;
        }
    }

    /* Set final sequence entry's next pointer to NULL */
    cur->next = NULL;

    if( *p != end )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}
/**
	特定结构类型 算法结构 的解析：
	AlgorithmIdentifier ::= SEQUENCE{
		algorithm		OBJECT IDENTIFIER,
		parameters		ANY DEFINED BY algorithm OPTIONAL		算法参数可以为 NULL, 也可以不止 1 个
	}
	AlgorithmIdentifier编码示意（与一般的SEQUENCE不同）：
	+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+
	| tag  |length|	tag  |length|value |value |value |value | tag  |length|value |value |value |value |value |value |
	|octet |octet |octet |octet |octet |octet |octet |octet |octet |octet |octet |octet |octet |octet |octet |octet |
	+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+
	
	                            |<-   algorithm value     ->|             |<-           parameters value          ->|
	              |<-                             AlgorithmIdentifier value                                       ->|
 */
int mbedtls_asn1_get_alg( unsigned char **p,		// p 指向 AlgorithmIdentifier 的 tlv
                  const unsigned char *end,
                  mbedtls_asn1_buf *alg, mbedtls_asn1_buf *params )		// alg 存储算法 oid；params 存储调用算法的特殊参数，可以为空
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_ASN1_OUT_OF_DATA );
	
    alg->tag = **p;			// p 指向 algorithm 的 tlv
    end = *p + len;			// len 是 algorithm 的 tlv 与 parameters 的 tlv 之和

    if( ( ret = mbedtls_asn1_get_tag( p, end, &alg->len, MBEDTLS_ASN1_OID ) ) != 0 )
        return( ret );

    alg->p = *p;
    *p += alg->len;		// 使 p 指向 parameters 的 tlv 

    if( *p == end )
    {
        mbedtls_platform_zeroize( params, sizeof(mbedtls_asn1_buf) );
        return( 0 );
    }

    params->tag = **p;
    (*p)++;

    if( ( ret = mbedtls_asn1_get_len( p, end, &params->len ) ) != 0 )
        return( ret );

    params->p = *p;
    *p += params->len;

    if( *p != end )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

int mbedtls_asn1_get_alg_null( unsigned char **p,		// 算法结构中参数为空的情形
                       const unsigned char *end,
                       mbedtls_asn1_buf *alg )
{
    int ret;
    mbedtls_asn1_buf params;

    memset( &params, 0, sizeof(mbedtls_asn1_buf) );

    if( ( ret = mbedtls_asn1_get_alg( p, end, alg, &params ) ) != 0 )
        return( ret );

    if( ( params.tag != MBEDTLS_ASN1_NULL && params.tag != 0 ) || params.len != 0 )
        return( MBEDTLS_ERR_ASN1_INVALID_DATA );

    return( 0 );
}

void mbedtls_asn1_free_named_data( mbedtls_asn1_named_data *cur )	// 释放 ANY DEFINED BY 中的一个节点，只清空节点内容，不对整个链进行重构
{
    if( cur == NULL )
        return;

    mbedtls_free( cur->oid.p );
    mbedtls_free( cur->val.p );

    mbedtls_platform_zeroize( cur, sizeof( mbedtls_asn1_named_data ) );
}

void mbedtls_asn1_free_named_data_list( mbedtls_asn1_named_data **head )	// 从前向后，释放 ANY DEFINED BY 的整个链
{
    mbedtls_asn1_named_data *cur;

    while( ( cur = *head ) != NULL )
    {
        *head = cur->next;
        mbedtls_asn1_free_named_data( cur );
        mbedtls_free( cur );
    }
}
/**
	对于类似于以下的ASN.1类型，根据 contentType，查找其对应的 content
	ContenInfo ::= SEQUENCE{
		contentType		ContentType,
		content		[0]	EXPLICIT ANY DEFINED BY contentType
	}
	ContentType ::= OBJECT IDENTIFIER
 */
mbedtls_asn1_named_data *mbedtls_asn1_find_named_data( mbedtls_asn1_named_data *list,
                                       const char *oid, size_t len )		//oid 是 __In, len 也是 __In
{
    while( list != NULL )
    {
        if( list->oid.len == len &&
            memcmp( list->oid.p, oid, len ) == 0 )
        {
            break;
        }

        list = list->next;
    }

    return( list );
}

#endif /* MBEDTLS_ASN1_PARSE_C */
