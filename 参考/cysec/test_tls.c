#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

#ifndef CYSEC_NO_TLS

/**
	验证证书链是否完整的回调
 */
static int tls_vcm_cb(X509CRT_PCTX crt, void *userdata){
	CERTMGR_PCTX cm = (CERTMGR_PCTX)userdata;
	int ret;

	if(!crt || !cm)
		return -1;

	printf("tls server certificate:\n");
	dumpcrt(crt);
	ret = cysec_certmgr_verify(cm, crt);
	s_assert((ret == 0), "Verify Certificate Chain Failure, ret = %08x\n", ret);
	
	return ret;
}

#if 0
/**
	测试tls客户端是否能与tls服务器连接成功
 */
static void test_ssl_one(void) {
	const char* p[] = { "rsa", "sm2", "ecc" };
	char path[256];
	unsigned int n, m; 
	int ret;
	int num;
	PKEY_PCTX pvk = NULL;
	X509CRT_PCTX crt = NULL;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";		//http请求字符串

	printf("tls client test ...\n");
	for (n = 0; n < sizeof(p)/sizeof(char*); n ++) {
		for (m = 0; m < 2; m ++) {
			TLS_CLIENT_PCTX ctx = tls_client_new();	

			tls_client_set_verify_callback(ctx, tls_vcb, NULL);
			if (m) {
				snprintf(path, sizeof(path), "%s/%s.ssl.pvk.pem", KPOOL_PATH, p[n]);
				pvk = FILE_getpvk(path);
				snprintf(path, sizeof(path), "%s/%s.ssl.crt.pem", KPOOL_PATH, p[n]);
				crt = FILE_getcrt(path);
				ret = tls_client_set_certificate(ctx, crt);
				s_assert((ret == 0), "ret=%08x", ret);
				ret = tls_client_set_private_key(ctx, pvk);
				s_assert((ret == 0), "ret=%08x", ret);
			}
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");
			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

			tls_client_free(ctx);
			
			if (m) {
				x509crt_free(crt);
				pkey_free(pvk);
			}
		}
	}
}
#endif

/**
	客户端与服务器的非安全连接benchmark时间测试（客户端不对服务端身份进行验证）
 */
static void test_ssl_benchmark_verify_none(const char *srvaddr, int port) {
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
	int ret = 0 ;
	size_t reqlen = strlen(req);
	const char *addr = NULL;
	
	if(!srvaddr)
		addr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
	else
		addr = srvaddr;

	printf("using remote server %s:%d.\n", addr, port);
	
	//benchmark连接测试，每次与服务器连接都构建一个客户端，连接之后立即断开立即，测试3s内的客户端连接数及吞吐量
	benchmark(1);
	while (_bm.loop) {
		//构造tls客户端句柄
		TLS_CLIENT_PCTX ctx = tls_client_new();
		//打开tls客户端，尝试与服务器连接
		ret = tls_client_connect(ctx, addr, port);
		if (ret) {
			printf("connect failed. exit!(%08x)\n",ret);
			exit (-1);
		}
		//客户端向服务端发送请求数据
		ret = tls_client_write(ctx, (const unsigned char *)req, reqlen);
		if (ret<=0) {
			printf("write req data failed. exit!\n");
			exit (-1);
		}
		//关闭与服务端的连接
		tls_client_close(ctx);
		//释放tls客户端
		tls_client_free(ctx);
		_bm.round ++;
	}
	benchmark(0);

	printf("tls client\ttime=%fs round=%d  %.2f/s\n", _bm.e, _bm.round, _bm.round/_bm.e);
}

/**
	客户端与服务器的安全连接benchmark时间测试（客户端验证服务端身份，单向认证）
 */
static void test_ssl_benchmark_verify_required(const char *srvaddr, int port, CERTMGR_PCTX cm, X509CRT_PCTX localcrt, PKEY_PCTX localpvk) {
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
	int ret = 0 ;
	size_t reqlen = strlen(req);
	const char *addr = NULL;

	if(!cm || !localcrt || !localpvk)
		return ;

	if(!srvaddr)
		addr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
	else
		addr = srvaddr;

	printf("using remote server %s:%d.\n", addr, port);
	
	benchmark(1);
	while (_bm.loop) {
		//构造tls客户端句柄
		TLS_CLIENT_PCTX ctx = tls_client_new();
		//客户端句柄绑定自身证书（请求服务器更新身份证书的需要）
		ret = tls_client_set_certificate(ctx, localcrt);
		s_assert((ret == 0), "ret=%08x", ret);
		//客户端句柄绑定自身密钥（请求服务器更新身份证书的需要）
		ret = tls_client_set_private_key(ctx, localpvk);
		s_assert((ret == 0), "ret=%08x", ret);	
		//tls客户端获得服务端身份证书后，将服务端身份证书添加进证书管理器中，之后客户端调用此回调验证服务端身份证书的证书链完整性
		tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);
		//打开tls客户端，尝试与服务器连接
		ret = tls_client_connect(ctx, addr, port);
		if (ret) {
			printf("connect failed. exit!(%08x)\n",ret);
			exit (-1);
		}
		//客户端向服务端发送请求数据
		ret = tls_client_write(ctx, (const unsigned char *)req, reqlen);
		if (ret<=0) {
			printf("write req data failed. exit!\n");
			exit (-1);
		}
		//关闭与服务端的连接
		tls_client_close(ctx);
		//释放tls客户端
		tls_client_free(ctx);
		_bm.round ++;
	}
	benchmark(0);

	printf("tls client\ttime=%fs round=%d  %.2f/s\n", _bm.e, _bm.round, _bm.round/_bm.e);

}

/**
	tls客户端向二级ca服务器发送消息，请求更新自己的身份证书（从客户端设置自己的身份证书和私钥猜测）
	但这里tls客户端与服务器连接之后立即断开，并没有做其他的工作，所以这里客户端发送私钥，甚至发送应
	该都是没必要的
 */
static int test_ssl_benchmark(void)
{
	const char* p[] = { "rsa", "sm2", "ecc" };
	char path[256];
	unsigned int n; 
	PKEY_PCTX pvk = NULL;
	X509CRT_PCTX crt = NULL;
	X509CRT_PCTX cacrt = NULL;
	X509CRT_PCTX rootcrt = NULL;
	CERTMGR_PCTX cm = NULL;
	const char* srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";

	printf("tls client test ...\n");
	for (n = 0; n < sizeof(p)/sizeof(char*); n ++) {
		test_ssl_benchmark_verify_none(srvaddr, 443+n*2);
	}

	for (n = 0; n < sizeof(p)/sizeof(char*); n ++) {
		//ca的自签名证书
		snprintf(path, sizeof(path), "%s/%s.ssl.rootcrt.pem", KPOOL_PATH, p[n] );
		rootcrt = FILE_getcrt(path);
		//二级ca证书，可以认为是服务器的证书
		snprintf(path, sizeof(path), "%s/%s.ssl.cacrt.pem", KPOOL_PATH, p[n] );
		cacrt = FILE_getcrt(path);
		//tls客户端私钥
		snprintf(path, sizeof(path), "%s/%s.ssl.pvk.pem", KPOOL_PATH, p[n]);
		pvk = FILE_getpvk(path);
		//tls客户端私钥
		snprintf(path, sizeof(path), "%s/%s.ssl.crt.pem", KPOOL_PATH, p[n]);
		crt = FILE_getcrt(path);
		//设置证书链
		cm = certmgr_new();
		certmgr_add_ca(cm, cacrt);
		certmgr_add_ca(cm, rootcrt);
		//测试
		test_ssl_benchmark_verify_required(srvaddr, 443+n*2+1,cm,crt,pvk);	
		//释放
		pkey_free(pvk);
		x509crt_free(cacrt);
		x509crt_free(crt);
		x509crt_free(rootcrt);
		certmgr_free(cm);
	}

	return 0;
}

/**
	Bob与Alice进行通话，在通话之前Bob想要确认Alice身份证书是否被吊销，于是Bob将Alice的身份证书发送给ocsp服务器，对Alice的身份予以确认.
	而ocsp服务器会返回给Bob一个ocsp响应内容，之后Bob调用下面的回调验证ocsp构造ocsp响应句柄并验证
	这里的Alice是二级ca证书服务器，是给Bob签发身份证书的服务器
 */
/** for testing usage, don't use for product.*/
static int test_ocspstapling_callback(X509CRT_PCTX ctx, unsigned char *ocspresponse, int olen, void *userdata)
{
	CERTMGR_PCTX cm = (CERTMGR_PCTX)userdata;
	OCSP_RESPONSE_PCTX rsp_ctx = NULL;
	X509CRT_PCTX signer = NULL;	
	unsigned int ocspstatus = 0, ocsp_certstatus = 0;
	int ret = -1;

	if( !ctx || !ocspresponse || olen <= 0 )
		return -1;
	//Bob根据响应内容构造ocsp响应句柄
	ret = cysec_ocsprsp_decode(ocspresponse, olen, &rsp_ctx);
	s_assert((ret == 0), "recevice an invalid OCSP response, %08x\n",ret);
	if(ret != 0 ) goto err;;
	//获取ocsp响应句柄的签发者证书，这里的签发者证书即为ocsp服务器身份证书
	//获取ocsp响应句柄的签名信息，ocsp服务器将验证消息使用自己的私钥签名后发送给Bob，这里是将ocsp服务器自己的身份证书（签发者证书）发送给Bob，
	//以此证明Alice的身份证书可信
	signer = cysec_ocsprsp_get_signer(rsp_ctx);
	//因为暂时无法与ocsp服务器连接，所以只能通过下面的方法来获取 signer，这是测试的需要，实际中不应该这样
	if(!signer)
		signer = cysec_certmgr_get_ocsprsp_signer(cm, rsp_ctx);	//kpool中也没有ocsp服务器的证书，所以此次 test_tls.c 是无法验证的
	if(!signer)
		goto err;
	//Bob已经有ocsp服务器身份证书的公钥，通过此公钥验证此签发者证书确是属于ocsp服务器，此时Bob确认Alice证书是否合法性完毕
	ret = cysec_ocsprsp_verify(rsp_ctx, signer);
	s_assert((ret == 0), "Verify Signature Failure, ret = %08x\n", ret);
	if(ret !=0 ) goto err;
	//签发者证书的证书链是否完整
	ret = cysec_certmgr_verify(cm, signer);
	s_assert((ret == 0), "Verify Certificate Chain Failure, ret = %08x\n", ret);
	if( ret != 0 ) goto err;
	//获取ocsp响应码
	ret = cysec_ocsprsp_get_rspstatus(rsp_ctx, &ocspstatus);
	s_assert((ret == 0), "failed to get rsp status %08x\n",ret);
	printf("rspstatus is %d\n",ocspstatus);
	if(ret != 0 || ocspstatus != 0) goto err;
	//获取ocsp响应证书状态码
	ret = cysec_ocsprsp_get_certstatus(rsp_ctx, ctx, cm, &ocsp_certstatus);
	s_assert((ret == 0), "failed to get cert status %08x\n", ret);
	printf("certstatus is %d\n", ocsp_certstatus);
	if(ret !=0 || ocsp_certstatus != 0) goto err;

	if(signer)
		x509crt_free(signer);
	if(rsp_ctx)
		cysec_ocsprsp_free(&rsp_ctx);
	return 0;
err:
	if(signer)
		x509crt_free(signer);
	if(rsp_ctx)
		cysec_ocsprsp_free(&rsp_ctx);

    return -(0x0000FFFF & ret);
}

/** ocsp stapling */
/**
	Bob（tls客户端）向Alice（二级ca证书服务器）请求更新自己的身份证书，非阻塞模式
 */
static void test_nonblocking_ssl_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (NONBLOCKING socket) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			TLS_CLIENT_PCTX ctx = NULL;
			
			printf("=========================================================\n");
			//获取tls客户端证书
			snprintf(path, sizeof(path), "./kpool/%s.ssl.crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;
			//获取ca的自签名证书
			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;
			//获取二级ca证书
			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;
			//获取客户端私钥
			snprintf(path, sizeof(path), "./kpool/%s.ssl.pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;
			//构造证书管理器
			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			//添加二级ca到管理器
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			//添加根证书到管理器
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			//构造tls客户端
			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			//Bob向ocsp服务器发送一个验证Alice证书状态的ocsp请求给ocsp服务器，ocsp服务器处理该请求后将结果以ocsp响应形式发送给Bob
			//Bob调用回调函数test_ocspstapling_callback处理此ocsp响应
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			//Bob验证Alice身份证书链是否完整
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);
			//Bob绑定自己的身份证书
			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			//Bob绑定自己的私钥
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			//Bob请求与Alice连接，srvaddr是Alice地址
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			//Bob向Alice发送数据
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");
			//Bob断开与Alice的连接
			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

/** ocsp stapling */
/**
	Bob（tls客户端）向Alice（二级ca证书服务器）请求更新自己的身份证书，阻塞模式
 */
static void test_blocking_ssl_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (BLOCKING socket) ...\n");
	printf("==================================\n");

	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			TLS_CLIENT_PCTX ctx =NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;
			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;
			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;
			snprintf(path, sizeof(path), "./kpool/%s.ssl.pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;

			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			//设置阻塞模式，超时时间内无法连接Alice，返回
			ret = cysec_tls_client_set_block_mode(ctx, CYSEC_TLS_CLIENT_BLOCK_MODE_BLOCK);
			if(ret)
				goto freebuffer;
			//阻塞超时设定
			ret = cysec_tls_client_set_rwtimeout(ctx, 5);
			if(ret)
				goto freebuffer;

			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

/**
	Bob的证书被撤销了，Bob（tls客户端）向Alice（二级ca证书服务器）请求更新自己的身份证书，非阻塞模式
	只是Bob的证书被撤销，在Alice不要求验证Bob证书的前提下，Bob可以请求到自己新的身份证书；否则就不行
 */
static void test_ssl_revoked_nonblocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (NONBLOCKING socket)(certificate revoked) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			TLS_CLIENT_PCTX ctx=NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			//Bob被注销的证书
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;
			//ca自签名证书
			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;
			//二级ca证书
			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;
			//Bob被注销的私钥
			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;
			//构造证书链
			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;

			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			//注意：这里是Bob发送请求到ocsp服务器验证Alice的身份是否合法，Bob的身份证书是否撤销无关于该步骤的执行
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			//注意：这里是验证Alice的证书链是否完整，与Bob证书是否被撤销无关
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);
			//虽然证书被摊销，但Bob还是要绑定自己的证书
			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			if(ret)
				goto freebuffer;
			//虽然是发送证书更新请求，但不排除Alice趁机对Bob的身份进行认证，此种情况下，因为Bob证书已被撤销而无法连接Alice
			//但证书更新请求时，Alice应该不会对Bob的身份进行认证
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

/**
	Bob的证书被撤销了，Bob（tls客户端）向Alice（二级ca证书服务器）请求更新自己的身份证书，阻塞模式
	只是Bob的证书被撤销，在Alice不要求验证Bob证书的前提下，Bob可以请求到自己新的身份证书；否则就不行
 */
static void test_ssl_revoked_blocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (BLOCKING socket)(certificate revoked) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			PKEY_PCTX pvk = NULL;
			X509CRT_PCTX rootcrt = NULL;
			TLS_CLIENT_PCTX ctx = NULL;
			char path[256] = {0};
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;


			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_block_mode(ctx, CYSEC_TLS_CLIENT_BLOCK_MODE_BLOCK);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_rwtimeout(ctx, 5);
			if(ret)
				goto freebuffer;

			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

/**
	Bob的证书过期了，Bob（tls客户端）向Alice（二级ca证书服务器）请求更新自己的身份证书，非阻塞模式
	只是Bob的证书过期了，在Alice不要求验证Bob证书的前提下，Bob可以请求到自己新的身份证书；否则就不行
 */
static void test_ssl_expired_nonblocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (NONBLOCKING socket)(certificate expired) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			TLS_CLIENT_PCTX ctx = NULL;
			//Bob过期的身份证书
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;
			//Bob过期的密钥
			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;

			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			//注意：这里是Bob发送请求到ocsp服务器验证Alice的身份是否合法，Bob的身份证书是否过期无关于该步骤的执行
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			//注意：这里是验证Alice的证书链是否完整，与Bob证书是否过期无关
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);
			//虽然证书过期，但Bob还是要绑定自己的证书
			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			if(ret)
				goto freebuffer;
			//虽然是发送证书更新请求，但不排除Alice趁机对Bob的身份进行认证，此种情况下，因为Bob会因证书过期而无法连接Alice
			//但证书更新请求时，Alice应该不会对Bob的身份进行认证
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:

			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

/**
	Bob的证书过期了，Bob（tls客户端）向Alice（二级ca证书服务器）请求更新自己的身份证书，阻塞模式
	只是Bob的证书过期了，在Alice不要求验证Bob证书的前提下，Bob可以请求到自己新的身份证书；否则就不行
 */
static void test_ssl_expired_blocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (BLOCKING socket)(certificate expired) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			TLS_CLIENT_PCTX ctx = NULL;
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;


			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_block_mode(ctx, CYSEC_TLS_CLIENT_BLOCK_MODE_BLOCK);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_rwtimeout(ctx, 5);
			if(ret)
				goto freebuffer;

			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.137";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

int main(void)
{

	test_nonblocking_ssl_certstatus();
	
	test_blocking_ssl_certstatus();


	test_ssl_revoked_nonblocking_certstatus();
	test_ssl_revoked_blocking_certstatus();
	test_ssl_expired_nonblocking_certstatus();
	test_ssl_expired_blocking_certstatus();
	//test_ssl_one();
	test_ssl_benchmark();
	return 0;
}

#else
int  main()
{
	return 0;
}

#endif //CYSEC_NO_TLS