/*******************************************************************************
*												*
*			CONFIDENTIAL VISTEON CORPORATION					*
*												*
* This is an unpublished work of authorship, which contains trade				*
* secrets, created in 2010. Visteon Corporation owns all rights to				*
* this work and intends to maintain it in confidence to preserve				*
* its trade secret status. Visteon Corporation reserves the right,				*
* under the copyright laws of the United States or those of any					*
* other country that may have jurisdiction, to protect this work				*
* as an unpublished work, in the event of an inadvertent or					*
* deliberate unauthorized publication. Visteon Corporation also					*
* reserves its rights under all copyright laws to protect this					*
* work as a published work, when appropriate. Those having access				*
* to this work may not copy it, use it, modify it or disclose the				*
* information contained in it without the written authorization					*
* of Visteon Corporation.									*
*																				*
*******************************************************************************/
/*******************************************************************************
* Module:			tls_test.c
* Description:		manage version
* Project Scope:
* Organization:		Yf-Visteon audio program
					Yf-Visteon Software Operation, China
					Yf-Visteon Corporation
* Version Control:
* Archive:
* Revision:
* Author:			xcai2
* Date:

--------------------------------------------------------------------------------
* Compiler Name:	GCC
* Target Hardware:	Linux PC
					

*******************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "cysec.h"
//#include "ubase64.h"
//#include "scep.h"

#ifndef CYSEC_NO_TLS
#if 1

/*===============================================
* Function  Name : TLS_RetrieveCertificate_File
* Description :  retrieve certificate from the file, auto detect DER or PEM format
* Parameter :   
		cert : output certificate as  X509CRT_PCTX structure
		PrivateKey : output private key as PKEY_PCTX structure
		FilePath : the path of certificate file
		type : 0 -> private key; 1 -> certificate
* Return : 
*		If return negative data, that means certificate parse error. 
		Otherwise, parse OK.
* ================================================*/
static int  TLS_RetrieveCertificate_File(X509CRT_PCTX* cert, PKEY_PCTX* PrivateKey, const char* FilePath, unsigned char type)
{
	FILE *f;
	size_t n;
	int ret = -1;
	unsigned char *buf = NULL;
	
	if( ( f = fopen( FilePath, "rb" ) ) == NULL )
	{
		printf("file open failed : \n");
	    return ret;
	}

	fseek( f, 0, SEEK_END );
	n = (size_t) ftell( f );
	fseek( f, 0, SEEK_SET );

	if( ( buf = malloc ( n + 1 ) ) == NULL )
	{
		fclose( f );
		printf("allocate buffer memory failed : \n");
	  	return ret;
	}

	if( fread( buf, 1, n, f ) != n )
	{
		fclose( f );
		free ( buf );
		printf("certificate file read failed : \n");
	  	return ret;
	}

	if(type == 1)/*certificate*/
	{
		if((*cert = cysec_x509crt_load(buf, n)) != NULL)
		{
			ret = 0;
		}
		else
		{
			printf("load certificate failed : \n");
		}
	}
	else/*private key*/
	{
		if((*PrivateKey = cysec_pkey_load_private(buf, n, NULL)) != NULL)
		{
			ret = 0;
			printf("total size of private key is %zu\n", n);
		}
		else
		{
			printf("load private key failed : \n");
		}
	}

	fclose(f);
	free(buf);
	return ret;
	
}

/*===============================================
* Function  Name : TLS_CertificateVerify_Callback
* Description :  call back function for verify certificate in certificate manager
* Parameter :   
		cert : output certificate as  X509CRT_PCTX structure
		PrivateKey : output private key as PKEY_PCTX structure
		FilePath : the path of certificate file
		type : 0 -> private key; 1 -> certificate
* Return : 
*		If return negative data, that means certificate parse error. 
		Otherwise, parse OK.
* ================================================*/
static int  TLS_CertificateVerify_Callback(X509CRT_PCTX cert, void* userdata)
{
	int ret;
	CERTMGR_PCTX CM = (CERTMGR_PCTX)userdata;

    ret = cysec_certmgr_verify(CM, cert);
    if(ret != 0){
        return  -(0x0000FFFF & ret);
    }

    return 0;
}

static void usage(void)
{
	printf("--capath the path/filename of CA certificate.\n");
	printf("--host the IP/domain of SSL server.\n");
	printf("--port the port of SSL server.\n");
	exit(0);
}

int main(int argc, char **argv)
{
	int ret = -1;
	CERTMGR_PCTX	cm = NULL;
	X509CRT_PCTX	cacert = NULL;
	TLS_CLIENT_PCTX	ctx = NULL;
	char message[] = "Hello, I am client!";
	//char read[4096];
	const char *host = NULL, *capath = NULL;
	int port = 0;

	argc--;
	argv++;

	while(argc > 0){
		if(strcmp(*argv,"--capath") == 0){
		  if(--argc<1)
		    break;
		  capath = *(++argv);
		}else if(strcmp(*argv,"--host") == 0){
		  if(--argc<1)
		    break;
		  host = *(++argv);
		} else if(strcmp(*argv,"--port") == 0) {
		  if(--argc<1)
		    break;
		  port = atoi(*(++argv));
		} 
		else
		  break;
		argc--;
		argv++;
	}

  if(!host||!capath||port == 0)
    usage();

	if((ret = TLS_RetrieveCertificate_File(&cacert, NULL, capath, 1)) != 0)
	{
		goto FAIL;
	}

	if((cm = certmgr_new()) == NULL)
	{
		goto FAIL;
	}

	if((ret = certmgr_add_ca(cm, cacert)) !=0 )
	{
		goto FAIL;
	}

	if((ctx = tls_client_new()) == NULL)
	{
		goto FAIL;
	}
	
	if((ret = tls_client_set_verify_callback(ctx, TLS_CertificateVerify_Callback, (void  *)cm)) != 0)
	{
		goto FAIL;
	}
	printf("come here1??\n");

	if((ret = tls_client_connect(ctx, host, port)) != 0)
	{
		goto FAIL;
	}
	printf("come here2??\n");

	tls_client_write(ctx, (const unsigned char *)message, sizeof(message));
	//tls_client_read(ctx, (unsigned char *)read, sizeof(read) - 1);
	/** 关闭SSL隧道(关闭Socket) */
	tls_client_close(ctx);
	tls_client_free(ctx);
	ctx = NULL;
	
FAIL:
	if(cacert)
		cysec_x509crt_free(cacert);
	if(cm)
		certmgr_free(cm);
	if(ctx)
		tls_client_free(ctx);
	
	printf("print (%08x)\n",ret);

	return 0;
}
#endif

#else
int  main()
{
	return 0;
}

#endif //CYSEC_NO_TLS


