#!/bin/sh
echo "======================="
echo "====== demo1 =========="
echo "======================="
valgrind --tool=memcheck --leak-check=full ./demo1 --capath ../test/kpool/rsa.ssl.cacrt.pem --host 192.168.10.130 --port 443 > /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo1 rsa failed."
	exit
fi

valgrind --tool=memcheck --leak-check=full ./demo1 --capath ../test/kpool/sm2.ssl.cacrt.pem --host 192.168.10.130 --port 445 >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo1 sm2 failed."
	exit
fi

valgrind --tool=memcheck --leak-check=full ./demo1 --capath ../test/kpool/ecc.ssl.cacrt.pem --host 192.168.10.130 --port 447  >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo1 ecc failed."
	exit
fi

echo "======================="
echo "====== demo2 =========="
echo "======================="
valgrind --tool=memcheck --leak-check=full ./demo2 --capath ../test/kpool/rsa.ssl.cacrt.pem --host 192.168.10.130 --port 443  >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo2 rsa failed."
	exit
fi

valgrind --tool=memcheck --leak-check=full ./demo2 --capath ../test/kpool/sm2.ssl.cacrt.pem --host 192.168.10.130 --port 445  >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo2 sm2 failed."
	exit
fi

valgrind --tool=memcheck --leak-check=full ./demo2 --capath ../test/kpool/ecc.ssl.cacrt.pem --host 192.168.10.130 --port 447  >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo2 ecc failed."
	exit
fi


echo "======================="
echo "====== demo3 =========="
echo "======================="
valgrind --tool=memcheck --leak-check=full ./demo3 --capath ../test/kpool/rsa.ssl.cacrt.pem --host 192.168.10.130 --port 444 --cert ../test/kpool/rsa.ssl.crt.pem --pvk ../test/kpool/rsa.ssl.pvk.pem  >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo1 rsa failed."
	exit
fi

valgrind --tool=memcheck --leak-check=full ./demo3 --capath ../test/kpool/sm2.ssl.cacrt.pem --host 192.168.10.130 --port 446 --cert ../test/kpool/sm2.ssl.crt.pem --pvk ../test/kpool/sm2.ssl.pvk.pem  >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo1 sm2 failed."
	exit
fi

valgrind --tool=memcheck --leak-check=full /demo3 --capath ../test/kpool/ecc.ssl.cacrt.pem --host 192.168.10.130 --port 448 --cert ../test/kpool/ecc.ssl.crt.pem --pvk ../test/kpool/ecc.ssl.pvk.pem  >> /tmp/cysec_demo_leak.log 2>&1
if [ $? -ne 0 ] ; then
	echo "demo1 ecc failed."
	exit
fi