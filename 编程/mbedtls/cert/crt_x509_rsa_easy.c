#include <stdio.h>
#include <stdint.h>

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#define mbedtls_printf       printf
#define mbedtls_fprintf      fprintf

#define mbedtls_err(ret)    \
do{ \
    char errbuf[1024];  \
    mbedtls_strerror(ret, errbuf, 1024);    \
    mbedtls_fprintf(stderr, "%d ret(%02x) : %s\n", __LINE__, ret, errbuf);          \
    goto cleanup;   \
}while(0);

// RSA CA证书
const char   mbedtls_test_ca_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDhzCCAm+gAwIBAgIBADANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MTcwNTA0MTY1NzAxWhcNMjcwNTA1MTY1NzAxWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n"
"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n"
"mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n"
"50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n"
"YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n"
"R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n"
"KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n"
"gZUwgZIwHQYDVR0OBBYEFLRa5KWz3tJS9rnVppUP6z68x/3/MGMGA1UdIwRcMFqA\r\n"
"FLRa5KWz3tJS9rnVppUP6z68x/3/oT+kPTA7MQswCQYDVQQGEwJOTDERMA8GA1UE\r\n"
"CgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0GCAQAwDAYDVR0T\r\n"
"BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAHK/HHrTZMnnVMpde1io+voAtql7j\r\n"
"4sRhLrjD7o3THtwRbDa2diCvpq0Sq23Ng2LMYoXsOxoL/RQK3iN7UKxV3MKPEr0w\r\n"
"XQS+kKQqiT2bsfrjnWMVHZtUOMpm6FNqcdGm/Rss3vKda2lcKl8kUnq/ylc1+QbB\r\n"
"G6A6tUvQcr2ZyWfVg+mM5XkhTrOOXus2OLikb4WwEtJTJRNE0f+yPODSUz0/vT57\r\n"
"ApH0CnB80bYJshYHPHHymOtleAB8KSYtqm75g/YNobjnjB6cm4HkW3OZRVIl6fYY\r\n"
"n20NRVA1Vjs6GAROr4NqW4k/+LofY9y0LLDE+p0oIEKXIsIvhPr39swxSA==\r\n"
"-----END CERTIFICATE-----\r\n";
// RSA CA证书长度
const size_t mbedtls_test_ca_crt_rsa_len = sizeof( mbedtls_test_ca_crt_rsa );
// RSA 客户端证书
const char mbedtls_test_cli_crt_rsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDhTCCAm2gAwIBAgIBBDANBgkqhkiG9w0BAQsFADA7MQswCQYDVQQGEwJOTDER\r\n"
"MA8GA1UECgwIUG9sYXJTU0wxGTAXBgNVBAMMEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"
"MTcwNTA1MTMwNzU5WhcNMjcwNTA2MTMwNzU5WjA8MQswCQYDVQQGEwJOTDERMA8G\r\n"
"A1UECgwIUG9sYXJTU0wxGjAYBgNVBAMMEVBvbGFyU1NMIENsaWVudCAyMIIBIjAN\r\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyHTEzLn5tXnpRdkUYLB9u5Pyax6f\r\n"
"M60Nj4o8VmXl3ETZzGaFB9X4J7BKNdBjngpuG7fa8H6r7gwQk4ZJGDTzqCrSV/Uu\r\n"
"1C93KYRhTYJQj6eVSHD1bk2y1RPD0hrt5kPqQhTrdOrA7R/UV06p86jt0uDBMHEw\r\n"
"MjDV0/YI0FZPRo7yX/k9Z5GIMC5Cst99++UMd//sMcB4j7/Cf8qtbCHWjdmLao5v\r\n"
"4Jv4EFbMs44TFeY0BGbH7vk2DmqV9gmaBmf0ZXH4yqSxJeD+PIs1BGe64E92hfx/\r\n"
"/DZrtenNLQNiTrM9AM+vdqBpVoNq0qjU51Bx5rU2BXcFbXvI5MT9TNUhXwIDAQAB\r\n"
"o4GSMIGPMB0GA1UdDgQWBBRxoQBzckAvVHZeM/xSj7zx3WtGITBjBgNVHSMEXDBa\r\n"
"gBS0WuSls97SUva51aaVD+s+vMf9/6E/pD0wOzELMAkGA1UEBhMCTkwxETAPBgNV\r\n"
"BAoMCFBvbGFyU1NMMRkwFwYDVQQDDBBQb2xhclNTTCBUZXN0IENBggEAMAkGA1Ud\r\n"
"EwQCMAAwDQYJKoZIhvcNAQELBQADggEBAC7yO786NvcHpK8UovKIG9cB32oSQQom\r\n"
"LoR0eHDRzdqEkoq7yGZufHFiRAAzbMqJfogRtxlrWAeB4y/jGaMBV25IbFOIcH2W\r\n"
"iCEaMMbG+VQLKNvuC63kmw/Zewc9ThM6Pa1Hcy0axT0faf1B/U01j0FIcw/6mTfK\r\n"
"D8w48OIwc1yr0JtutCVjig5DC0yznGMt32RyseOLcUe+lfq005v2PAiCozr5X8rE\r\n"
"ofGZpiM2NqRPePgYy+Vc75Zk28xkRQq1ncprgQb3S4vTsZdScpM9hLf+eMlrgqlj\r\n"
"c5PLSkXBeLE5+fedkyfTaLxxQlgCpuoOhKBm04/R1pWNzUHyqagjO9Q=\r\n"
"-----END CERTIFICATE-----\r\n";
// RSA 客户端证书长度
const size_t mbedtls_test_cli_crt_rsa_len = sizeof( mbedtls_test_cli_crt_rsa );

/**
    功能：
        解析 RSA 证书
    说明：
        1.对证书内容的学习可以参考 struct mbedtls_x509_crt 结构(位于x509_crt.h中）；
        2.
 */
int main(int argc, char *argv[])
{
    int ret = 0;
    uint32_t flags;
    mbedtls_x509_crt cacert_ctx;
    mbedtls_x509_crt clicert_ctx;
    //初始化证书结构体
    mbedtls_x509_crt_init(&cacert_ctx);
    mbedtls_x509_crt_init(&clicert_ctx);
    //ca证书内容同构
    if ((ret = mbedtls_x509_crt_parse(&cacert_ctx, (const unsigned char *)mbedtls_test_ca_crt_rsa, mbedtls_test_ca_crt_rsa_len)) != 0)
        mbedtls_err(ret);
    //clinet证书内容同构
    if ((ret = mbedtls_x509_crt_parse(&clicert_ctx, (const unsigned char*)mbedtls_test_cli_crt_rsa, mbedtls_test_ca_crt_rsa_len)) != 0)
        mbedtls_err(ret);
    //证书验证
    if ((ret = mbedtls_x509_crt_verify(&clicert_ctx, &cacert_ctx, NULL, NULL, &flags, NULL, NULL)) != 0)
        mbedtls_err(ret);
    
cleanup:
    mbedtls_fprintf(stderr, "ret (%08X)\n", ret);
    mbedtls_x509_crt_free(&cacert_ctx);
    mbedtls_x509_crt_free(&clicert_ctx);
    
    return ret;
}