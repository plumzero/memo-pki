#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <mbedsm2.h>

#define s_assert(v, fmt, arg...) \
	do { \
		if(!(v)) { \
			printf("[ASSERT] %s:%d " fmt "\n", __FILE__,__LINE__,##arg);\
		}\
	} while(0)

static void test_hex_dump(const char *desc,
			const unsigned char *data, size_t data_cb) {
    size_t i = 0, k = 0;
    char hexline[126] = "";
    char hexbytes[11] = "";

    printf("%s :\n", desc);

    for (i=0; i<data_cb; i++) {
    	sprintf(hexbytes, "0x%02X|", data[i]);
    	strcat(hexline, hexbytes);

    	if ((((i+1)%16==0) && (i!=0)) || (i+1==data_cb)) {
    		k++;
    		printf("l%zu: %s\n", k, hexline);
    		memset(&hexline[0],0, sizeof(hexline));
    	}
    }
}

static int test_gen_key(MBEDSM2_PKEY_CTX client, MBEDSM2_PKEY_CTX server)
{
	int ret = 0;
	unsigned char P1[128] = {0};
	unsigned char P[128] = {0};
	size_t p1len = 0, plen = 0;

	if(!client || !server )
		return -1;

	ret = libmbedsm2_client_ecp_genkey_step_one(client, 
		P1, sizeof(P1), &p1len);
	s_assert((ret == 0), "Client: genkey step one error.(%08x)\n", ret);

	ret = libmbedsm2_server_ecp_genkey(server, P1, p1len, P, sizeof(P), &plen);
	s_assert((ret == 0), "Server: genkey step error.(%08x)\n", ret);

	ret = libmbedsm2_client_ecp_genkey_step_two(client, P, plen);
	s_assert((ret == 0), "Client: genkey step two error.(%08x)\n", ret);

	test_hex_dump("the public key", P, plen);

	return ret;
}

static int test_print_key(MBEDSM2_PKEY_CTX client, MBEDSM2_PKEY_CTX server)
{
	int ret = 0;
	unsigned char public_x_client[128] = {0};
	unsigned char public_y_client[128] = {0};
	unsigned char prikey_client[128] = {0};
	unsigned char public_x_server[128] = {0};
	unsigned char public_y_server[128] = {0};
	unsigned char prikey_server[128] = {0};
	size_t public_x_client_len = 0, public_y_client_len = 0,
		public_x_server_len = 0, public_y_server_len = 0,
		prikey_client_len = 0, prikey_server_len = 0;

	if(!client || !server)
		return -1;

	ret = libmbedsm2_ecp_pkey_export_pubkey(client, 
		public_x_client, sizeof(public_x_client), &public_x_client_len, 
		public_y_client, sizeof(public_y_client), &public_y_client_len);
	if(ret) {
		printf("Client: export public key error. (%d)\n", ret);
		return -1;
	}

	test_hex_dump("client: public key x", public_x_client, public_x_client_len);
	test_hex_dump("client: public key y", public_y_client, public_y_client_len);

	ret = libmbedsm2_ecp_pkey_export_pubkey(server, 
		public_x_server, sizeof(public_x_server), &public_x_server_len, 
		public_y_server, sizeof(public_y_server), &public_y_server_len);
	if(ret) {
		printf("Server: export public key error. (%d)\n", ret);
		return -1;
	}

	test_hex_dump("server: public key x", public_x_server, public_x_server_len);
	test_hex_dump("server: public key y", public_y_server, public_y_server_len);

	if(public_x_server_len != public_x_client_len ||
		public_y_client_len != public_y_server_len ||
		memcmp(public_x_client, public_x_server, public_x_client_len) != 0 ||
		memcmp(public_y_client, public_y_server, public_y_client_len) != 0 )
	{
		printf(" the server and client's public key is mismatch.\n");
		return -1;
	}

	ret = libmbedsm2_ecp_pkey_export_private_key( client, prikey_client, sizeof(prikey_client),
		&prikey_client_len);
	if(ret) {
		printf("Client, export private key error.(%d)\n", ret);
		return -1;
	}

	test_hex_dump("Client: private key.", prikey_client, prikey_client_len);

	ret = libmbedsm2_ecp_pkey_export_private_key( server, prikey_server, sizeof(prikey_server),
		&prikey_server_len);
	if(ret) {
		printf("Server, export private key error.(%d)\n", ret);
		return -1;
	}

	test_hex_dump("Server: private key.", prikey_server, prikey_server_len);

	return 0;
}

static int test_load_pkey(MBEDSM2_PKEY_CTX client)
{
	MBEDSM2_PKEY_CTX client1 = NULL;
	int ret = 0;
	unsigned char public_x_client[128] = {0};
	unsigned char public_y_client[128] = {0};
	unsigned char prikey_client[128] = {0};
	unsigned char public_x_client1[128] = {0};
	unsigned char public_y_client1[128] = {0};
	unsigned char prikey_client1[128] = {0};
	size_t public_x_client_len = 0, public_y_client_len = 0,
		public_x_client1_len = 0, public_y_client1_len = 0,
		prikey_client_len = 0, prikey_client1_len = 0;

	if(!client )
		return -1;

	ret = libmbedsm2_ecp_pkey_export_pubkey(client, 
		public_x_client, sizeof(public_x_client), &public_x_client_len, 
		public_y_client, sizeof(public_y_client), &public_y_client_len);
	if(ret) {
		printf("Client: export public key error. (%d)\n", ret);
		return -1;
	}

	test_hex_dump("client: public key x", public_x_client, public_x_client_len);
	test_hex_dump("client: public key y", public_y_client, public_y_client_len);

	ret = libmbedsm2_ecp_pkey_export_private_key( client, prikey_client, sizeof(prikey_client),
		&prikey_client_len);
	if(ret) {
		printf("Client, export private key error.(%d)\n", ret);
		return -1;
	}
	test_hex_dump("Client: private key.", prikey_client, prikey_client_len);

	client1 = libmbedsm2_pkey_new();
	if(!client1) {
		printf("out of memory.\n");
		return -1;
	}

	ret = libmbedsm2_ecp_pkey_load(client1, 
			prikey_client, prikey_client_len,
			public_x_client, public_x_client_len,
			public_y_client, public_y_client_len
			);

	if(ret) {
		printf("load ecp failed.\n");
		libmbedsm2_pkey_free(client1);
		return -1;
	}

	ret = libmbedsm2_ecp_pkey_export_pubkey(client1, 
		public_x_client1, sizeof(public_x_client1), &public_x_client1_len, 
		public_y_client1, sizeof(public_y_client1), &public_y_client1_len);
	if(ret) {
		printf("Client: export public key error. (%d)\n", ret);
		libmbedsm2_pkey_free(client1);
		return -1;
	}

	test_hex_dump("client1: public key x", public_x_client1, public_x_client1_len);
	test_hex_dump("client1: public key y", public_y_client1, public_y_client1_len);

	ret = libmbedsm2_ecp_pkey_export_private_key( client1, prikey_client1, sizeof(prikey_client1),
		&prikey_client1_len);
	if(ret) {
		printf("Client, export private key error.(%d)\n", ret);
		libmbedsm2_pkey_free(client1);
		return -1;
	}

	test_hex_dump("Client1: private key.", prikey_client1, prikey_client1_len);

	if(public_x_client_len != public_x_client1_len ||
		public_y_client_len != public_y_client1_len ||
		prikey_client_len != prikey_client1_len ||
		memcmp(public_x_client, public_x_client1, public_x_client1_len) != 0 ||
		memcmp(public_y_client, public_y_client1, public_y_client1_len) != 0 ||
		memcmp(prikey_client, prikey_client1, prikey_client1_len) != 0 )
	{
		printf("the load key is mismatch origin key.\n");
		libmbedsm2_pkey_free(client1);
		return -1;
	}

	libmbedsm2_pkey_free(client1);
	return 0;	

}

static int test_fill_buf(unsigned char *buf, size_t blen)
{
	int  i = 0;

	if(!buf || blen == 0)
		return -1;

	for( i=0; i < blen; i++ )
		buf[i] = i;

	return 0;
}

static int test_ecdsa_plain(MBEDSM2_PKEY_CTX client, MBEDSM2_PKEY_CTX server)
{

	int ret = 0;
	MBEDSM2_ECDSA_CONTEXT ecdsa = NULL;
	unsigned char buf[112] = {0};
	unsigned char e[32], Q1[128], r[32], s2[128], s3[128], 
		out[128], rtmp[64], stmp[64];
	size_t elen = 0, q1len = 0, rlen = 0, s2len = 0, s3len = 0, 
		olen = 0, rtmplen = 0, stmplen =0;

	if(!client || !server )
		return -1;

	ecdsa = libmbedsm2_ecdsa_new();
	if(!ecdsa)
		return -1;

	ret = test_fill_buf(buf, sizeof(buf));
	s_assert((ret == 0), "fill buf.(%08x)\n", ret);	

	test_hex_dump("plain", buf, sizeof(buf));
	ret = libmbedsm2_client_ecp_ecdsa_sign_step_one(ecdsa, client, buf, sizeof(buf), 
			e, sizeof(e), &elen,
			Q1, sizeof(Q1), &q1len);

	s_assert((ret == 0),"Client: sign step one.(%08x)\n", ret);
	test_hex_dump("e", e, elen);
	test_hex_dump("q1", Q1, q1len);

	ret = libmbedsm2_server_ecp_ecdsa_sign(server, e, elen, Q1, q1len,
			r, sizeof(r), &rlen,
			s2, sizeof(s2), &s2len,
			s3, sizeof(s3), &s3len);
	s_assert((ret == 0),"Server: sign error.(%08x)\n", ret);
	test_hex_dump("r", r, rlen);
	test_hex_dump("s2", s2, s2len);
	test_hex_dump("s3", s3, s3len);

	ret = libmbedsm2_client_ecp_ecdsa_sign_step_two(ecdsa, client, r, rlen, s2, s2len, 
			s3, s3len, out, sizeof(out), &olen);
	s_assert((ret == 0),"Client: sign step two.(%08x)\n", ret);	
	test_hex_dump("sig", out, olen);

	ret = libmbedsm2_client_ecp_ecdsa_export_rs(out, olen, rtmp, sizeof(rtmp), &rtmplen,
			stmp, sizeof(stmp), &stmplen);
	s_assert((ret == 0),"Client: export r, s error.(%08x)\n", ret);	
	test_hex_dump("r", rtmp, rtmplen);
	test_hex_dump("s", stmp, stmplen);

	ret = libmbedsm2_ecp_ecdsa_verify(client, buf, sizeof(buf), out, olen);
	s_assert((ret == 0),"Client: verify error.(%08x)\n", ret);	

	ret = libmbedsm2_ecp_ecdsa_digest_verify(client, e, elen, out, olen);
	s_assert((ret == 0),"Client: Digest verify error.(%08x)\n", ret);	

	ret = libmbedsm2_ecp_ecdsa_verify(server, buf, sizeof(buf), out, olen);
	s_assert((ret == 0),"Server: verify error.(%08x)\n", ret);	

	ret = libmbedsm2_ecp_ecdsa_digest_verify(server, e, elen, out, olen);
	s_assert((ret == 0),"Server: Digest verify error.(%08x)\n", ret);	

	libmbedsm2_ecdsa_free(ecdsa);
	return ret;
}	

static int test_ecdsa_hash(MBEDSM2_PKEY_CTX client, MBEDSM2_PKEY_CTX server)
{

	int ret = 0;
	MBEDSM2_ECDSA_CONTEXT ecdsa = NULL;
	unsigned char buf[112] = {0};
	unsigned char e[32], Q1[128], r[32], s2[128], s3[128], 
		out[128], rtmp[64], stmp[64];
	size_t elen = 32, q1len = 0, rlen = 0, s2len = 0, s3len = 0, 
		olen = 0, rtmplen = 0, stmplen =0;

	if(!client || !server )
		return -1;

	ecdsa = libmbedsm2_ecdsa_new();
	if(!ecdsa)
		return -1;

	ret = test_fill_buf(buf, sizeof(buf));
	s_assert((ret == 0), "fill buf.(%08x)\n", ret);	
	test_hex_dump("plain", buf, sizeof(buf));

	ret = mbedsm2_sm2hash(buf, sizeof(buf), client, e);
	s_assert((ret == 0), "mbedsm2_hash buf.(%08x)\n", ret);	
	test_hex_dump("e", e, elen);

	ret = libmbedsm2_client_ecp_ecdsa_digest_sign_step_one(ecdsa, client,
			Q1, sizeof(Q1), &q1len);

	s_assert((ret == 0),"Client: sign step one.(%08x)\n", ret);
	test_hex_dump("q1", Q1, q1len);

	ret = libmbedsm2_server_ecp_ecdsa_sign(server, e, elen, Q1, q1len,
			r, sizeof(r), &rlen,
			s2, sizeof(s2), &s2len,
			s3, sizeof(s3), &s3len);
	s_assert((ret == 0),"Server: sign error.(%08x)\n", ret);
	test_hex_dump("r", r, rlen);
	test_hex_dump("s2", s2, s2len);
	test_hex_dump("s3", s3, s3len);

	ret = libmbedsm2_client_ecp_ecdsa_sign_step_two(ecdsa, client, r, rlen, s2, s2len, 
			s3, s3len, out, sizeof(out), &olen);
	s_assert((ret == 0),"Client: sign step two.(%08x)\n", ret);	
	test_hex_dump("sig", out, olen);

	ret = libmbedsm2_client_ecp_ecdsa_export_rs(out, olen, rtmp, sizeof(rtmp), &rtmplen,
			stmp, sizeof(stmp), &stmplen);
	s_assert((ret == 0),"Client: export r, s error.(%08x)\n", ret);	
	test_hex_dump("r", rtmp, rtmplen);
	test_hex_dump("s", stmp, stmplen);

	ret = libmbedsm2_ecp_ecdsa_verify(client, buf, sizeof(buf), out, olen);
	s_assert((ret == 0),"Client: verify error.(%08x)\n", ret);	

	ret = libmbedsm2_ecp_ecdsa_digest_verify(client, e, elen, out, olen);
	s_assert((ret == 0),"Client: Digest verify error.(%08x)\n", ret);	

	ret = libmbedsm2_ecp_ecdsa_verify(server, buf, sizeof(buf), out, olen);
	s_assert((ret == 0),"Server: verify error.(%08x)\n", ret);	

	ret = libmbedsm2_ecp_ecdsa_digest_verify(server, e, elen, out, olen);
	s_assert((ret == 0),"Server: Digest verify error.(%08x)\n", ret);	

	libmbedsm2_ecdsa_free(ecdsa);
	return ret;
}	

static int test_ecies(MBEDSM2_PKEY_CTX client, MBEDSM2_PKEY_CTX server)
{
	int ret = 0;
	unsigned char buf[112] = {0};
	unsigned char t1[128] = {0}, t2[128] = {0};
	unsigned char c[2048] = {0}, plain[2048] = {0};
	size_t clen = 0, t1len = 0, t2len = 0, plen = 0;

	if(!client || !server )
		return -1;

	ret = test_fill_buf(buf, sizeof(buf));
	s_assert((ret == 0), "fill buf.(%08x)\n", ret);	

	test_hex_dump("plain", buf, sizeof(buf));
	ret = libmbedsm2_ecp_ecies_encrypt(server, buf, sizeof(buf), c, sizeof(c), &clen);
	s_assert((ret == 0),"encrypt error.(%08x)\n",ret);

	test_hex_dump("encrypt:", c, clen);
	ret = libmbedsm2_client_ecp_ecies_decrypt_step_one(client, c, clen, t1, sizeof(t1), &t1len);
	s_assert((ret == 0), "Client: decrypt step one .error = %08x\n", ret);
	test_hex_dump("t1", t1, t1len);

	ret = libmbedsm2_server_ecp_ecies_decrypt(server, t1, t1len, t2, sizeof(t2), &t2len);
	s_assert((ret == 0), "Server: decrypt .error = %08x\n", ret);
	test_hex_dump("t2", t2, t2len);

	ret = libmbedsm2_client_ecp_ecies_decrypt_step_two(client, c, clen, t2, t2len, plain, sizeof(plain), &plen);
	s_assert((ret == 0), "Client: decrypt step two .error = %08x\n", ret);	
	test_hex_dump("decrypt", plain, plen);

	s_assert((plen == sizeof(buf) && memcmp(plain, buf, plen) == 0), " decrypt error.");
	return ret;
}

static int test_ecies_by_data(MBEDSM2_PKEY_CTX client,MBEDSM2_PKEY_CTX server)
{
	unsigned char data[] = {0x30,0x81,0xD9,0x02,0x20,0x43,0x04,0xD1,0x3D,0x49,0x07,0xE1,0x5A,0x08,0xFE,0xE1,
0x85,0x3C,0xE7,0xD5,0x57,0xA0,0x55,0x08,0xBA,0x4A,0xF7,0x68,0xE3,0xB1,0x77,0x15,
0xED,0xB5,0xB8,0x49,0xED,0x02,0x21,0x00,0x82,0x6C,0x8C,0x2D,0x53,0xC9,0x6D,0x2F,
0x3F,0xA5,0x58,0x76,0x65,0x49,0x0C,0x94,0x0B,0x67,0x69,0x8F,0x42,0xCB,0x37,0x00,
0x49,0xB0,0x6A,0x62,0xF1,0x97,0xCC,0xE4,0x04,0x20,0x33,0xA6,0x78,0x37,0xDF,0x97,
0x7D,0xCA,0x70,0x1D,0x5C,0x12,0x51,0xD4,0xA3,0xFF,0x8D,0xB1,0x0E,0x13,0x1D,0x19,
0xD9,0x3A,0x0B,0x24,0x9D,0xC5,0x0B,0x4D,0x12,0xC2,0x04,0x70,0x4A,0x20,0xA2,0x4C,
0x31,0x91,0xAE,0x19,0x02,0xD6,0xD7,0xCA,0xD3,0xA1,0x87,0x8E,0x8F,0x2D,0xF7,0xAA,
0x75,0x2D,0x1D,0xD2,0xFB,0x29,0x06,0xE2,0xBD,0xF2,0xEB,0xA7,0x60,0x59,0xC0,0x84,
0x74,0x96,0xDF,0xC3,0x0F,0x20,0x4A,0x01,0xB4,0x1E,0x6D,0xE5,0x30,0x9F,0x9B,0x50,
0xD0,0xC7,0xB2,0xE0,0x9C,0xCB,0x2D,0x8E,0x3A,0x7E,0x4F,0xCF,0xAD,0x78,0x42,0x66,
0x80,0x9C,0x99,0x86,0x7D,0xED,0xB0,0xF3,0xED,0xAB,0x12,0x97,0x14,0x50,0x73,0xED,
0xAE,0xED,0x95,0xF9,0x4B,0xB9,0x9D,0x37,0x9C,0x9F,0xFC,0x7B,0x4A,0x66,0xD4,0x5C,
0x7D,0x05,0x02,0x73,0x95,0xF5,0xE6,0x95,0x0D,0xE3,0x73,0xBF};
	unsigned char t2[] = {0x04,0x2C,0xA8,0xDE,0x76,0x46,0x06,0xAF,0x8F,0x9B,0x2E,0x56,0x98,0xDD,0x95,0x14,
0x4C,0xFD,0xF8,0x7B,0xC6,0x71,0x51,0x92,0x35,0x2E,0x13,0x66,0xC7,0x09,0xA2,0xCF,
0x84,0x6D,0xC8,0x24,0xD5,0x59,0xBE,0x1A,0xFD,0xCB,0x9A,0x22,0xFB,0xBC,0x10,0x38,
0x37,0x45,0x0C,0x98,0xF2,0xE8,0x9F,0xA1,0xEE,0x4E,0xF1,0x51,0x4D,0x19,0x55,0xBF,
0x69,};

	unsigned char plain[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,
0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,
0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,};
	size_t plen = sizeof(plain);
	size_t t2len = sizeof(t2);
	size_t dlen = sizeof(data);
	unsigned char tmp[2048] = {0};
	size_t tlen = 0;
	int ret = 0;

	ret = libmbedsm2_client_ecp_ecies_decrypt_step_two(client, data, dlen, t2, t2len, tmp, sizeof(tmp), &tlen);
	s_assert((ret == 0), "Client: decrypt step two .error = %08x\n", ret);	
	test_hex_dump("decrypt", tmp, tlen);

	s_assert((tlen == plen && memcmp(plain, tmp, plen) == 0), " decrypt error.");
	return ret;

}

int main(int argc, char **argv)
{
	MBEDSM2_PKEY_CTX client = NULL, server = NULL;
	int ret = 0;

	client = libmbedsm2_pkey_new();
	if(!client){
		printf("out of memory.\n");
		exit(-1);
	}

	server = libmbedsm2_pkey_new();
	if(!server){
		printf("out of memory.\n");
		goto end;
	}

	ret = test_gen_key(client,server);
	if(ret){
		printf("generate key failed.\n");
		goto end;
	}

	ret = test_print_key(client, server);
	if(ret) {
		printf("print key error.\n");
		goto end;
	}

	ret = test_load_pkey(client);
	if(ret) {
		printf("load pkey failed.\n");
		goto end;
	}

	ret = test_ecdsa_plain(client, server);
	if(ret){
		printf("ecdsa failed.\n, ret=%08x\n", ret);
		goto end;
	}

	ret = test_ecdsa_hash(client, server);
	if(ret){
		printf("ecdsa failed.\n, ret=%08x\n", ret);
		goto end;
	}

	ret = test_ecies(client, server);
	if(ret){
		printf("ecies failed.\n, ret=%08x\n", ret);
		goto end;
	}

	ret = test_ecies_by_data(client, server);
	if(ret){
		printf("ecies failed by data.\n, ret=%08x\n", ret);
		goto end;		
	}

	printf("all test passed.\n");

end:
	libmbedsm2_pkey_free(client);
	libmbedsm2_pkey_free(server);

	exit(ret);
}