#!/bin/sh
echo "=================================="
echo "=======It is testing cipher ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full ./test_cipher > /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_cipher failed."
	exit
fi

echo "=================================="
echo "=======It is testing csr ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full  ./test_csr >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_csr failed."
	exkt
fi

echo "=================================="
echo "=======It is testing digest ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full ./test_digest >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_csr failed."
	exit
fi

echo "=================================="
echo "=======It is testing hmac ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full  ./test_hmac >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_hmac failed."
	exit
fi

echo "=================================="
echo "=======It is testing  mgr ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full  ./test_mgr >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_mgr failed."
	exit
fi

echo "=================================="
echo "=======It is testing ocsp ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full ./test_ocsp >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_ocsp failed."
	exit
fi

echo "=================================="
echo "=======It is testing pkcs7 ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full ./test_pkcs7 >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_pkcs7 failed."
	exit
fi

echo "=================================="
echo "=======It is testing pkey ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full  ./test_pkey >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_pkey failed."
	exit
fi

echo "=================================="
echo "=======It is testing scep ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full  ./test_scep_pkcsreq >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_scep failed."
	exit
fi

echo "=================================="
echo "=======It is testing tls ======"
echo "=================================="
valgrind --tool=memcheck --leak-check=full  ./test_tls >> /tmp/cysec_test_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "test_tls failed."
	exit
fi