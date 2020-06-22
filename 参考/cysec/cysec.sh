#!/bin/sh

if [ -e $1 ] && [ -f $1 ]; then
	rm -f $1
fi

echo "wait for some time..."

echo "========================="
echo "======= HASH测试 ========"
echo "========================="
gcc -g -o2 test_digest.c test_util.c -o test_digest -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_digest failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_digest >> $1
else
	./test_digest
fi
	
if [ $? -ne 0 ]; then
	echo "execute test_digest failed"
	exit 1
fi
echo "======= HASH完成 ========"

echo "========================="
echo "======= HMAC测试 ========"
echo "========================="
gcc -g -o2 test_hmac.c test_util.c -o test_hmac -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_hmac failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_hmac >> $1
else
	./test_hmac
fi

if [ $? -ne 0 ]; then
	echo "execute test_hmac failed"
	exit 1
fi
echo "======= HMAC完成 ========"

echo "========================="
echo "==== 对称加解密测试 ====="
echo "========================="
gcc -g -o2 test_cipher.c test_util.c -o test_cipher -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_cipher failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_cipher >> $1
else
	./test_cipher
fi

if [ $? -ne 0 ]; then
	echo "execute test_cipher failed"
	exit 1
fi
echo "==== 对称加解密完成 ====="

echo "========================="
echo "===== pkcs7签名测试 ====="
echo "========================="
gcc -g -o2 test_pkcs7.c test_util.c -o test_pkcs7 -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_pkcs7 failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_pkcs7 >> $1
else
	./test_pkcs7
fi

if [ $? -ne 0 ]; then
	echo "execute test_pkcs7 failed"
	exit 1
fi
echo "===== pkcs7签名完成 ====="

echo "========================="
echo "===== 签名摘要测试 ======"
echo "===== 密钥接口测试 ======"
echo "=== 非对称加解密测试 ===="
echo "========================="
gcc -g -o2 test_pkey.c test_util.c -o test_pkey -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_pkey failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_pkey >> $1
else
	./test_pkey
fi

if [ $? -ne 0 ]; then
	echo "execute test_pkey failed"
	exit 1
fi
echo "===== 签名摘要完成 ======"
echo "===== 密钥接口完成 ======"
echo "=== 非对称加解密完成 ===="


echo "========================="
echo "===== SCEP接口测试 ======"
echo "========================="
gcc -g -o2 test_scep_pkcsreq.c test_util.c -o test_scep_pkcsreq -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_scep_pkcsreq failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_scep_pkcsreq >> $1
else
	./test_scep_pkcsreq
fi

if [ $? -ne 0 ]; then
	echo "execute test_scep_pkcsreq failed"
	exit 1
fi
echo "===== SCEP接口完成 ======"

echo "========================="
echo "===== SCEP接口测试 ======"
echo "========================="
gcc -g -o2 test_scep_renewalreq.c test_util.c -o test_scep_renewalreq -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_scep_renewalreq failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_scep_renewalreq >> $1
else
	./test_scep_renewalreq
fi

if [ $? -ne 0 ]; then
	echo "execute test_scep_renewalreq failed"
	exit 1
fi
echo "===== SCEP接口完成 ======"


echo "========================="
echo "===== OCSP接口测试 ======"
echo "========================="
gcc -g -o2 test_ocsp.c test_util.c -o test_ocsp -I$CYSEC/include -L$CYSEC/lib -lcysec
if [ $? -ne 0 ]; then
	echo "generate test_ocsp failed"
	exit 1
fi

if [ $# -ge 1 ]; then
	./test_ocsp >> $1
else
	./test_ocsp
fi

if [ $? -ne 0 ]; then
	echo "execute test_ocsp failed"
	exit 1
fi
echo "===== OCSP接口完成 ======"

echo "========================="
echo "====== TLS连接测试 ======"
echo "========================="
gcc -g -o2 test_tls.c test_util.c -o test_tls -I$CYSEC/include -L$CYSEC/lib -lcysec



echo "========================="
echo "==== 随机数生成测试 ====="
echo "========================="


gcc -g test_csr.c test_util.c -o test_csr -I$CYSEC/include -L$CYSEC/lib -lcysec

gcc -g test_mgr.c test_util.c -o test_mgr -I$CYSEC/include -L$CYSEC/lib -lcysec

gcc -g test_pkey_pair_check.c test_util.c -o test_pkey_pair_check -I$CYSEC/include -L$CYSEC/lib -lcysec

gcc -g test_pkey.c test_util.c -o test_pkey -I$CYSEC/include -L$CYSEC/lib -lcysec


gcc -g tls.c test_util.c -o tls -I$CYSEC/include -L$CYSEC/lib -lcysec

cysec_pkey_gen_rsa 无法生成密钥

cysec_scep_response_decode 出现assert。 可能原因：无法确认rsa.scep.certrep.der和sm2.scep.certrep.der是什么文件所致


gcc -g  tls.c test_util.c -o tls -I$CYSEC/include -L$CYSEC/lib -lcysec

gcc -g  12.c test_util.c -o 12 -I$CYSEC/include -L$CYSEC/lib -lcysec

gcc -g  pkey.c test_util.c -o pkey -I$CYSEC/include -L$CYSEC/lib -lcysec












