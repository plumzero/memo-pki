// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>

// #include "mbedtls/config.h"
// #include "mbedtls/havege.h"

// #define mbedtls_printf          printf
// #define mbedtls_fprintf          fprintf

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_HAVEGE_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/havege.h"

#include <stdio.h>
#include <time.h>
#endif

/**
 使用基于硬件的可易变性熵源收集扩展器（havege）生成伪随机数
 havege不适用于虚拟机环境，依赖于时间和处理器特征
 缺省情况下没有配置havege，故暂时无法编译成功
 */
int main( int argc, char *argv[] )
{
    int i, k, ret = 0;
    FILE *f;
    time_t t;
    unsigned char buf[1024];
    
    mbedtls_havege_state hs;

    if( argc < 2 )
    {
        mbedtls_fprintf( stderr, "usage: %s <output filename>\n", argv[0] );
        return -1;
    }
    
    if ((f = fopen( argv[1], "wb+" )) == NULL)
    {
        mbedtls_printf( "failed to open '%s' for writing.\n", argv[1] );
        return -1;
    }

    mbedtls_havege_init(&hs);

    t = time(NULL);

    //反复调用，生成足够长度的伪随机数
    for( i = 0, k = 768; i < k; i++ )
    {
        if((ret = mbedtls_havege_random(&hs, buf, sizeof( buf ))) != 0)
            goto exit;

        fwrite(buf, sizeof( buf ), 1, f);

        fflush(stdout);
    }

    if(t == time( NULL ))
        t--;
exit:
    mbedtls_printf("ret (0x%08X)\n", ret);
    mbedtls_havege_free( &hs );
    fclose( f );
    return ret;
}