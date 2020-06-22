#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <cysec.h>
#include "test_util.h"

#ifndef CYSEC_NO_OCSP

#define TEST_E_NETWORK  0x10000
#define TEST_E_GETHOSTNAME TEST_E_NETWORK + 1
#define TEST_E_SOCKET TEST_E_NETWORK + 2
#define TEST_E_CONNECT  TEST_E_NETWORK + 3
#define TEST_E_SEND   TEST_E_NETWORK + 4
#define TEST_E_RECEVICE   TEST_E_NETWORK + 5
#define TEST_E_ADD_HTTP_HEADER TEST_E_NETWORK + 6
#define TEST_E_REMOVE_RESPONSE TEST_E_NETWORK + 7 

/**
	ocsp，可以看作是crl的替代品
 */
 /**
	接收http响应内容
  */
static int recv_timeout(int socket_fd, int timeout, unsigned char **out)
{
	int size_recv, total_size = 0;
	char recv_buff[1024];
	double timediff;
	struct timeval begin, now;
	unsigned char  *newout = NULL;
	int pre_total_size = 0;

	if(!out)
		return 0;

	//make socket non blocking
	fcntl(socket_fd, F_SETFL, O_NONBLOCK);

	//beginning time
	gettimeofday(&begin, NULL);
	*out = NULL;

	while(1)
	{
		gettimeofday(&now, NULL);

		//time elapsed in seconds
        timediff = (now.tv_sec - begin.tv_sec) ;
         
        //if you got some data, then break after timeout
        if( total_size > 0 && timediff > timeout )
        {
            break;
        }
         
        //if you got no data at all, wait a little longer, twice the timeout
        else if( timediff > timeout * 2)
        {
            break;
        }
         
        memset(recv_buff ,0 , sizeof(recv_buff));  //clear the variable
        if((size_recv =  recv(socket_fd , recv_buff , sizeof(recv_buff) , 0) ) < 0)
        {
            //if nothing was received then we want to wait a little before trying again, 0.1 seconds
            usleep(100000);
        }
        else
        {
        	pre_total_size = total_size;
        	total_size += size_recv;
        	newout = realloc(*out, total_size);
        	if(!newout){
        		free(*out);
        		return 0;
        	}
        	memcpy(newout + pre_total_size, recv_buff, size_recv);
        	*out = newout;
            //reset beginning time
            gettimeofday(&begin , NULL);
        }
	}

	return total_size;
}

/**
	功能：为ocsp请求添加http请求头
	@param	address		ocsp服务器地址
	@param	port		ocsp服务器端口
	@param	in			编码后的ocsp请求内容
	@param	ilen		编码后的ocsp请求内容长度
	@param	out			向ocsp服务器发送的请求内容
 */
static size_t add_httpheader(const char *address, int port, const unsigned char *in, size_t ilen,  unsigned char **out)
{
    size_t header_size = 0, total_size = 0;
    char tmp_buf[16] = {0};

    if(!in || !out)
        return 0;

    total_size += ilen;

    header_size += strlen("POST / HTTP/1.1\r\nHost: :\r\n");
    header_size += strlen("User-Agent: PECL::HTTP/1.6.6 (PHP/4.4.9)\r\n");
    header_size += strlen("Accept: */*\r\n");
    header_size += strlen("Content-Length: \r\n");
    header_size += strlen("Content-Type: application/x-www-form-urlencoded\r\n\r\n");
    sprintf(tmp_buf, "%d", port);
    header_size += strlen(address) + strlen(tmp_buf);
    memset(tmp_buf, 0, sizeof(tmp_buf));
    sprintf(tmp_buf, "%zu", ilen);
    header_size += strlen(tmp_buf);
    total_size += header_size;

    *out = calloc(1, total_size);
    if(!*out){
        return 0;
    }

    sprintf((char *)*out,"POST / HTTP/1.1\r\nHost: %s:%d\r\n", address, port);
    strcat((char *)*out,"User-Agent: PECL::HTTP/1.6.6 (PHP/4.4.9)\r\n");
    strcat((char *)*out,"Accept: */*\r\n");
    sprintf((char *)*out + strlen((char *)*out),"Content-Length: %zu\r\n", ilen);
    strcat((char *)*out,"Content-Type: application/x-www-form-urlencoded\r\n\r\n");
    memcpy(*out+strlen((char *)*out), in, ilen);

    return total_size;
}

/**
	功能：将http响应头内容删去，只保留http包体内容
 */
static size_t remove_httpheader(const unsigned char *in ,size_t ilen, unsigned char **out)
{
    char *str_in = (char *)in;
    char *ocsp_body = NULL, *content_length = NULL,*p;
    char length_str[16] = {0};
    int i=0;
    size_t ret=0;

    if(!in || (ilen == 0) || !out)
        return 0;

    ocsp_body = strstr(str_in, "\r\n\r\n");
    if(!ocsp_body)
        return 0;
    else
        ocsp_body += 4;

    content_length = strstr(str_in, "Content-Length");
    if(!content_length)
        return 0;
    else
        content_length += 15;

    p = content_length;
    while( *p != '\r'){
        length_str[i] = *p;
        i++;
        p++;
    }

    ret = atoi(length_str);
    *out=calloc(1, ret+1);
    if(!(*out))
        return 0;

    memcpy(*out, ocsp_body, ret);
    return ret;
}

//only for testing....don't copy

/**
	@param	address		ocsp服务器地址
	@param	port		ocsp服务器端口
	@param	in			编码后的ocsp请求
	@param	ilen		编码后的ocsp请求的长度
	@param	out			ocsp响应内容
	@param	olen		ocsp响应内容长度（http的响应body）
 */
int test_http_post(const char *address, int port, const unsigned char *in, size_t ilen, unsigned char **out, size_t *olen)
{
	struct sockaddr_in server_info;
    struct hostent *he;
    int socket_fd;
    char send_buff[1024];
    size_t tlen = 0;
    int ret = 0;
    unsigned char *http_request = NULL, *ocsp_response = NULL;
    size_t http_req_len = 0, ocsp_rsp_len = 0;
    unsigned char *p=NULL;

	//获取ocsp服务器主机信息
    he = gethostbyname(address);
    if(!he)
    	return TEST_E_GETHOSTNAME;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd == -1){
    	return TEST_E_SOCKET;
    }
	//Bob设置要与ocsp服务器的通信协议及ocsp地址&端口
    memset(&server_info, 0 , sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(port);
    server_info.sin_addr = *((struct in_addr *)he->h_addr);
	//Bob尝试与ocsp服务器建立连接
    ret = connect(socket_fd, (struct sockaddr *)&server_info, sizeof(struct  sockaddr));
    if(ret < 0){
    	return TEST_E_CONNECT;
    }
	//在发送请求之前，Bob对http请求头内容，内容在http_request中
    http_req_len = add_httpheader(address, port, in, ilen, &http_request);
    if(http_req_len == 0)
        return TEST_E_ADD_HTTP_HEADER;

    ilen = http_req_len;
    p = http_request;
    tlen = ilen;
	//Bob发送http请求给ocsp服务器
    while(1){
    	if(sizeof(send_buff) >= tlen ){
    		memset(send_buff, 0, sizeof(send_buff));
    		memcpy(send_buff, p, tlen);
    		if((send(socket_fd, send_buff, tlen, 0)) == -1){
    			printf("Failure sending message\n");
                free(http_request);
    			close(socket_fd);
    			return TEST_E_SEND;
    		}
    		break;
    	}else{
    		memset(send_buff, 0, sizeof(send_buff));
    		memcpy(send_buff, p, sizeof(send_buff));
    		p += sizeof(send_buff);
    		tlen -= sizeof(send_buff);
    		if((send(socket_fd, send_buff, sizeof(send_buff), 0))){
    			printf("Failure sending message\n");
                free(http_request);
    			close(socket_fd);
    			return TEST_E_SEND;
    		}
    	}
    }

    //printf("Sent successfully\n");
	//Bob接收http响应，并设置超时机制
    ocsp_rsp_len = recv_timeout(socket_fd, 2, &ocsp_response);
    if(ocsp_rsp_len <=0 ){
    	printf("Failure recevicing message\n");
        free(http_request);
    	close(socket_fd);
    	return TEST_E_RECEVICE;
    }

    close(socket_fd);
    *olen = remove_httpheader(ocsp_response, ocsp_rsp_len, out);
    if(*olen == 0){
        free(http_request);
        return TEST_E_REMOVE_RESPONSE;
    }

    free(http_request);
    if(ocsp_response)
        free(ocsp_response);
    return 0;
}

/**
	不要跟 test_tls.c 的Alice和Bob混淆
	功能：根据在线证书状态协议（OCSP）来确定身份证书是否有效
	1.验证者根据待验证证书信息，构造一个ocsp请求句柄发送给ocsp服务器
	2.ocsp服务器获取请求句柄后，进行处理，返回一个ocsp响应信息给验证者
	3.验证者根据ocsp响应信息构造ocsp响应句柄，并检测此响应句柄与请求句柄是否匹配
	4.若匹配，验证者就可以从ocsp响应句柄中或证书管理器中获取签发者证书，即ocsp服务器的身份证书
	5.验证者根据签发者公钥确认签发者证书的真实性
	6.验证者检测签发者证书链是否完整
	7.获取ocsp响应码及响应状态，从而判断要验证证书的是否有效
 */
void test_ocsp(void) {
	const char* p[] = { "rsa.n", "rsa.r", "sm2.n", "sm2.r", "ecc.n", "ecc.r" };
	char *address = NULL;
	int port = 0;
	int n, m, ret;

	for (n = 0; n < 2; n ++) {
		for ( m = 0; m < 2; m++ ){
			CERTMGR_PCTX ctx = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX signer = NULL;	
			char path[256] = {0};
			unsigned char* request = NULL, *response = NULL;
			size_t reqlen = 0, rsplen = 0;
			unsigned int ocspstatus = 0, ocsp_certstatus = 0;
            OCSP_REQUEST_PCTX req_ctx = NULL;
            OCSP_RESPONSE_PCTX rsp_ctx = NULL; 
			//获取Bob的证书
			snprintf(path, sizeof(path), "./kpool/%s.crt.pem", p[n*2 + m ]);
			crt = FILE_getcrt(path);
            if(!crt){
                printf("The certificate (%s) is invalid.\n",path);
                break;
            }
			//获取Alice的证书（二级ca证书）
			snprintf(path, sizeof(path), "./kpool/%s.rootcrt.pem", p[n*2 + m] );
			cacrt = FILE_getcrt(path);
            if(!crt){
                printf("The CA certificate (%s) is invalid.\n",path);
                break;
            }
			//构造证书管理器
			ctx = certmgr_new();
			//添加Alice证书
			ret = certmgr_add_ca(ctx, cacrt);
			s_assert((ret == 0), "ret=%d\n", ret);
			//根据待验证证书crt构造ocsp请求句柄
			//Bob想要与Alice进行通信，通信之前，Bob想确认自己的身份证书是否合法，所以发送一个ocsp请求（句柄）给ocsp服务器进行验证
			req_ctx = cysec_ocspreq_new(crt, ctx);		
			s_assert((req_ctx != NULL), "Failure new ocspreq\n");
			//Bob对ocsp请求句柄进行编码
			ret = cysec_ocspreq_encode(req_ctx, &request, &reqlen);
			s_assert((ret == 0),"ret = %d\n", ret);
			//Bob序列化ocsp请求句柄
            snprintf(path, sizeof(path), "./kpool/%s.ocspreq.der", p[n*2 + m]);
            FILE_putcontent(request, reqlen, path);

			//Bob获取ocsp服务器地址和端口
			port = 2560 + n;
			address = getenv("OCSP_SERVER_ADDR") ? getenv("OCSP_SERVER_ADDR") : "192.168.20.165";
			printf("connecting %s:%d \n", address, port);
			//与test_tls.c不同，这里并未将ocsp响应放到一个回调中去处理，所以test_http_post能否成功接收response内容直接关乎后续验证的成败
			//测试时要注意对test_http_post返回值的观察
			ret = test_http_post(address, port, request, reqlen, (unsigned char **)&response, &rsplen);
			s_assert((ret == 0), "ret = %d\n", ret);
			if(ret != 0)
				break;
			//Bob对ocsp服务器发回的ocsp响应内容解码，构造ocsp响应句柄
			ret = cysec_ocsprsp_decode(response, rsplen, &rsp_ctx);
			s_assert((ret == 0), "recevice an invalid OCSP response, %08x\n",ret);
			//Bob检测ocsp请求句柄和ocsp响应句柄是否匹配(Bob可以使用ocsp服务器的公钥对ocsp服务器发来的签名进行验证，以确认句柄是否匹配。不过从下面看，应该不是这种验证方法)
			ret = cysec_ocsprsp_check(req_ctx, rsp_ctx);
			s_assert((ret == 0), "Malware response, ret = %08x\n", ret);
			//Bob从ocsp响应句柄中获取签发者证书(即ocsp服务器的身份证书)
			signer = cysec_ocsprsp_get_signer(rsp_ctx);
			//如果ocsp响应句柄中没有提供签发者证书，就根据ocsp响应句柄内容从证书管理器中获取签发者证书
			if(!signer)
				signer = cysec_certmgr_get_ocsprsp_signer(ctx, rsp_ctx);
            if(!signer){
                printf("Failed to get signer.\n");
                break;
            }
			//Bob已经有ocsp服务器身份证书的公钥，通过此公钥验证此签发者证书确是属于ocsp服务器，此时Bob确认自己证书是否合法性完毕
			ret = cysec_ocsprsp_verify(rsp_ctx,signer);
			s_assert((ret == 0), "Verify Signature Failure, ret = %08x\n", ret);
			//Bob检测签发者证书链是否完整
			ret = cysec_certmgr_verify(ctx, signer);
			s_assert((ret == 0), "Verify Certificate Chain Failure, ret = %08x\n", ret);
			//获取ocsp响应码（如果获取ocsp响应失败可以根据响应码确定原因）
			ret = cysec_ocsprsp_get_rspstatus(rsp_ctx, &ocspstatus);
			s_assert((ret == 0), "failed to get rsp status %08x\n",ret);
			printf("rspstatus is %d\n",ocspstatus);
			//获取ocsp响应句柄状态码，以此判断证书crt的状态（正常，注销，未知等待）
			ret = cysec_ocsprsp_get_certstatus(rsp_ctx, crt, ctx, &ocsp_certstatus);
			s_assert((ret == 0), "failed to get cert status %08x\n", ret);
			printf("certstatus is %d\n", ocsp_certstatus);

			if(req_ctx)
				cysec_ocspreq_free(&req_ctx);
			if(rsp_ctx)
				cysec_ocsprsp_free(&rsp_ctx);

			if(ctx)
				certmgr_free(ctx);

			if(signer)
				x509crt_free(signer);

			if(cacrt)
				x509crt_free(cacrt);

			if(crt)
				x509crt_free(crt);
			
			if(request)
				SAFE_FREE(request);
			if(response)
				SAFE_FREE(response);			
		}

	}
}

int main(void)
{
	test_ocsp();
    exit(0);
}

#else
int  main()
{
    return 0;
}

#endif //CYSEC_NO_OCSP