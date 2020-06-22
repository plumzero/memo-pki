/*
 * ASN.1 buffer writing functionality
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

#if defined(MBEDTLS_ASN1_WRITE_C)

#include "mbedtls/asn1write.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/**
	对传入之前的p指向的位置和start位置进行一个图示.
	无论对 tlv 中的 t 或者 l 或者 v 进行编码，start 是一个固定哨兵，指向 t 或者 l 或者 v 的首址，p是一个游值（从后向前）
	对于 UNIVERSAL 标签类型：
	+------+------+------+
	| tag  |length|  unused    
	|octet |octet |    buf
	+------+------+------+
			  ↑      ↑
			start    p
	对于 CONTEXT-SPECIFIC 标签类型（以length octet记录两个长度位为例）：
	+------+------+------+------+------+
	|tag   |length| len  | len  |  unused
	|octet |octet |octet |octet |    buf
	+------+------+------+------+------+
               ↑                    ↑
			 start                  p
 */
/**
	长度串编码
	p 		指向 tlv-l 后面的一个字节（地址）
	start	指向 tlv-l 的首地址
	len		内容串编码长度
	返回，写入的长度，即 tlv-l 的大小
 */
int mbedtls_asn1_write_len( unsigned char **p, unsigned char *start, size_t len )		// 返回写入的 八位组 的个数
{
    if( len < 0x80 )		// 短型长度串编码
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (unsigned char) len;
        return( 1 );
    }
	
    if( len <= 0xFF )		// 长型长度串编码，大端存储
    {
        if( *p - start < 2 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = (unsigned char) len;
        *--(*p) = 0x81;
        return( 2 );
    }

    if( len <= 0xFFFF )
    {
        if( *p - start < 3 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = 0x82;
        return( 3 );
    }

    if( len <= 0xFFFFFF )
    {
        if( *p - start < 4 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = 0x83;
        return( 4 );
    }

#if SIZE_MAX > 0xFFFFFFFF
    if( len <= 0xFFFFFFFF )
#endif
    {
        if( *p - start < 5 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = ( len       ) & 0xFF;
        *--(*p) = ( len >>  8 ) & 0xFF;
        *--(*p) = ( len >> 16 ) & 0xFF;
        *--(*p) = ( len >> 24 ) & 0xFF;
        *--(*p) = 0x84;
        return( 5 );
    }

#if SIZE_MAX > 0xFFFFFFFF
    return( MBEDTLS_ERR_ASN1_INVALID_LENGTH );				// mbedtls 认为，内容字符串的长度不会超过 0xFFFFFFFF 个字节
#endif
}
/**
	标识串编码
	p 		指向 tlv-t 后面的一个字节（地址）
	start	指向 tlv-t 的首地址
	tag		标识值
	返回，写入的长度。在 mbedtls 中，统一使用低标识编码，占用 1 个字节。
 */
int mbedtls_asn1_write_tag( unsigned char **p, unsigned char *start, unsigned char tag )
{
    if( *p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = tag;

    return( 1 );
}
/**
	标识串编码
	p 		指向 tlv-v 后面的一个字节（地址）
	start	指向 tlv-v 的首地址
	buf		内容串地址
	size	内容串长度
	返回，写入的长度，即内容串的长度。
 */
int mbedtls_asn1_write_raw_buffer( unsigned char **p, unsigned char *start,
                           const unsigned char *buf, size_t size )
{
    size_t len = 0;

    if( *p < start || (size_t)( *p - start ) < size )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = size;
    (*p) -= len;
    memcpy( *p, buf, len );

    return( (int) len );
}
/**
	大整数编码。tlv 中，先编码 v，再编码 l，最后编码 t 。
 */
#if defined(MBEDTLS_BIGNUM_C)
int mbedtls_asn1_write_mpi( unsigned char **p, unsigned char *start, const mbedtls_mpi *X )
{
    int ret;
    size_t len = 0;

    // Write the MPI
    //
    len = mbedtls_mpi_size( X );

    if( *p < start || (size_t)( *p - start ) < len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    (*p) -= len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( X, *p, len ) );		// 编码 tlv-v: 大整数写入 p 中

    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    if( X->s ==1 && **p & 0x80 )		// 大数表示负数，且大数长度超过 128 个字节，则 ...
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;					// ... 在内容串前填充 0x00，同时长度串编码值加 1
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );					// 编码 tlv-l
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_INTEGER ) );	// 编码 tlv-t

    ret = (int) len;

cleanup:
    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C */
/**
	NULL 编码。只编码 tlv-t 和 tlv-l
 */
int mbedtls_asn1_write_null( unsigned char **p, unsigned char *start )	//只写 tlv 中的 t 和 l
{
    int ret;
    size_t len = 0;

    // Write NULL
    //
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, 0) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_NULL ) );

    return( (int) len );
}
/**
	OID，即 OBJECT IDENTIFIER 编码。
 */
int mbedtls_asn1_write_oid( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len )
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start,
                                  (const unsigned char *) oid, oid_len ) );
    MBEDTLS_ASN1_CHK_ADD( len , mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len , mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OID ) );

    return( (int) len );
}

/**
	AlgorithmIdentifier 编码。
	对于 tlv-v，
	如果调用的参数长度 par_len 不为 0，则在对 AlgorithmIdentifier 编码之前，参数已经编码成 tlv 格式
	了，传入的 par_len 只是其长度。
	如果调用的参数长度 par_len 为 0，则在该函数内编码。
	
	上述两种情况下，传入的 p 所指向的位置是不一样的：
	前者指向调用参数 tlv 的下一个位置；
	后者指向 oid tlv 的下一个位置
	
	返回，tlv 的长度，其中 v 包括算法oid和算法调用参数
 */
int mbedtls_asn1_write_algorithm_identifier( unsigned char **p, unsigned char *start,
                                     const char *oid, size_t oid_len,
                                     size_t par_len )
{
    int ret;
    size_t len = 0;

    if( par_len == 0 )		// 算法调用参数为空
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_null( p, start ) );
    else
        len += par_len;		// 猜测：参数就是一个 tlv

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid, oid_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}
/**
	BOOLEAN 类型编码。
 */
int mbedtls_asn1_write_bool( unsigned char **p, unsigned char *start, int boolean )
{
    int ret;
    size_t len = 0;

    if( *p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = (boolean) ? 255 : 0;
    len++;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BOOLEAN ) );

    return( (int) len );
}
/**
	INTEGER 编码。
 */
int mbedtls_asn1_write_int( unsigned char **p, unsigned char *start, int val )
{
    int ret;
    size_t len = 0;

    if( *p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
	
#ifdef DEBUG_LB

/**
	with 0x1234 (binary: 10010 00110100) as an example:
	tag - length - value  -> INTEGER - 2 - 00110100 00010010
	look follow:
	+------+------+------+------+------+
	| tag  |length|value |value |
	|octet |octet |octet |octet |
	+------+------+------+------+------+
	  0x02   0x04   0x34   0x12
	 ↑ start is fixed 		        ↑ p operate begin at here
	   at here
 */

#define ciL		(sizeof(uint32_t))
#define biL		(ciL << 3)
	size_t i, bits;
	uint32_t mask;
	
	mask = (uint32_t)1 << ( biL - 1 );
	bits = biL;
	
	for ( i = 0; i < ciL; i++ )
	{
		if ( val & mask ) break;
		
		bits--;
		mask >>= 1;
	}
	
	len = bits / 8 + ( bits % 8 ? 1 : 0 );
	
	size_t order = len;
	
	while ( order-- > 0 )
		*--(*p) = val >> (order << 3);		//little-endian
	
#else
	
    len += 1;		// 对 INTEGER 的编码应该为基本类型，其内容串的长度应该包括 1 个或多个八位组。 
    *--(*p) = val;
	/**
		保证ASN.1对整数的编码规则
		如果 INTERGER 内容串多于 1 个八位组，则第一个八位组的所有位和第二个八位组的第8位应满足：
			不全为 1
			不全为 0
	 */
    if( val > 0 && **p & 0x80 )	// 为正整数时，如果第 8 位为 1，会被认为是负数。为此需在这之前填充一个 0x00 字节
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }
	
#endif
	
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_INTEGER ) );

    return( (int) len );
}
/**
	PrintableString 编码。
 */
int mbedtls_asn1_write_printable_string( unsigned char **p, unsigned char *start,
                                 const char *text, size_t text_len )
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start,
                  (const unsigned char *) text, text_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_PRINTABLE_STRING ) );

    return( (int) len );
}
/**
	IA5String 编码。
 */
int mbedtls_asn1_write_ia5_string( unsigned char **p, unsigned char *start,
                           const char *text, size_t text_len )
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start,
                  (const unsigned char *) text, text_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_IA5_STRING ) );

    return( (int) len );
}

/**
	对 BIT STRING 的编码：
		+------+------+------+------+------+------+------+
		| tag  |length|value |value |value | ...  |value |
		|octet |octet |octet |octet |octet | ...  |octet |
		+------+------+------+------+------+------+------+
		|BIT   |len=  |unused|val[0]|val[1]| ...  |val[si|
		|STRING|size+1| bits |      |      | ...  | ze-1]|
		+------+------+------+------+------+------+------+
		              |<-          size + 1            ->|
 */
int mbedtls_asn1_write_bitstring( unsigned char **p, unsigned char *start,
                          const unsigned char *buf, size_t bits )
{
    int ret;
    size_t len = 0, size;

    size = ( bits / 8 ) + ( ( bits % 8 ) ? 1 : 0 );		// 存储比特串的字节，向上取整

    // Calculate byte length
    //
    if( *p < start || (size_t)( *p - start ) < size + 1 )	// 这个 1 是用来记录 unused bits 的
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = size + 1;
    (*p) -= size;
    memcpy( *p, buf, size );

    // Write unused bits
    //
    *--(*p) = (unsigned char) (size * 8 - bits);

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BIT_STRING ) );

    return( (int) len );
}
/**
	OCTET STRING 编码。
 */
int mbedtls_asn1_write_octet_string( unsigned char **p, unsigned char *start,
                             const unsigned char *buf, size_t size )
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start, buf, size ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );

    return( (int) len );
}
/**
	应该是扩展项。包括扩展项标识与扩展项信息。
	返回，新的扩展项节点指针。
 */
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data( mbedtls_asn1_named_data **head,
                                        const char *oid, size_t oid_len,
                                        const unsigned char *val,
                                        size_t val_len )
{
    mbedtls_asn1_named_data *cur;

    if( ( cur = mbedtls_asn1_find_named_data( *head, oid, oid_len ) ) == NULL )	// 如果没有找到，就存入新的条目
    {
        // Add new entry if not present yet based on OID
        //
        cur = (mbedtls_asn1_named_data*)mbedtls_calloc( 1,
                                            sizeof(mbedtls_asn1_named_data) );
        if( cur == NULL )
            return( NULL );

        cur->oid.len = oid_len;
        cur->oid.p = mbedtls_calloc( 1, oid_len );
        if( cur->oid.p == NULL )
        {
            mbedtls_free( cur );
            return( NULL );
        }

        memcpy( cur->oid.p, oid, oid_len );

        cur->val.len = val_len;
        cur->val.p = mbedtls_calloc( 1, val_len );
        if( cur->val.p == NULL )
        {
            mbedtls_free( cur->oid.p );
            mbedtls_free( cur );
            return( NULL );
        }

        cur->next = *head;		// 添加到链表的最后边
        *head = cur;
    }
    else if( cur->val.len < val_len )	// 修改扩展项标识对应的扩展项信息，可能需要为扩展项信息重新分配存储。
    {
        /*
         * Enlarge existing value buffer if needed
         * Preserve old data until the allocation succeeded, to leave list in
         * a consistent state in case allocation fails.
         */
        void *p = mbedtls_calloc( 1, val_len );
        if( p == NULL )
            return( NULL );

        mbedtls_free( cur->val.p );
        cur->val.p = p;
        cur->val.len = val_len;
    }

    if( val != NULL )
        memcpy( cur->val.p, val, val_len );

    return( cur );
}
#endif /* MBEDTLS_ASN1_WRITE_C */
