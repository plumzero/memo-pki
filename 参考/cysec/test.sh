#!/bin/sh
echo "=================================="
echo "=======It is testing cipher ======"
echo "=================================="
./test_cipher
if [ $? -ne 0 ] ; then
	echo "test_cipher failed."
	exit
fi

echo "=================================="
echo "=======It is testing csr ======"
echo "=================================="
./test_csr
if [ $? -ne 0 ] ; then
	echo "test_csr failed."
	exkt
fi

echo "=================================="
echo "=======It is testing digest ======"
echo "=================================="
./test_digest
if [ $? -ne 0 ] ; then
	echo "test_csr failed."
	exit
fi

echo "=================================="
echo "=======It is testing hmac ======"
echo "=================================="
./test_hmac
if [ $? -ne 0 ] ; then
	echo "test_hmac failed."
	exit
fi

echo "=================================="
echo "=======It is testing  mgr ======"
echo "=================================="
./test_mgr
if [ $? -ne 0 ] ; then
	echo "test_mgr failed."
	exit
fi

echo "=================================="
echo "=======It is testing ocsp ======"
echo "=================================="
./test_ocsp
if [ $? -ne 0 ] ; then
	echo "test_ocsp failed."
	exit
fi

echo "=================================="
echo "=======It is testing pkcs7 ======"
echo "=================================="
./test_pkcs7
if [ $? -ne 0 ] ; then
	echo "test_pkcs7 failed."
	exit
fi

echo "=================================="
echo "=======It is testing pkey ======"
echo "=================================="
./test_pkey
if [ $? -ne 0 ] ; then
	echo "test_pkey failed."
	exit
fi

echo "=================================="
echo "=======It is testing scep ======"
echo "=================================="
./test_scep
if [ $? -ne 0 ] ; then
	echo "test_scep failed."
	exit
fi

echo "=================================="
echo "=======It is testing tls ======"
echo "=================================="
./test_tls
if [ $? -ne 0 ] ; then
	echo "test_tls failed."
	exit
fi