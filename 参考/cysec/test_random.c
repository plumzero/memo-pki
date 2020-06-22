#include <stdio.h>
#include <cysec.h>
#include "test_util.h"

/**
 * 生成随机数
 * @param  buf 缓冲区, 用于存放生成的随机数
 * @param  num 期望的随机数字节数
 * @return     成功 -> 0, 失败 -> 其它
 */
// CYSEC_RET cysec_random_generate(unsigned char* buf, size_t num);

static void test_random_generate()
{
	int size[] = {16, 64, 256, 1024, 4096};
	int i, ret;
	unsigned char *p = NULL;
	for (i = 0; i < sizeof(size)/sizeof(int); i++)
	{
		p = calloc(size[i], sizeof(unsigned char));
		ret = cysec_random_generate(p, size[i]);
		s_assert((ret == 0), "generate random failed");
		if (p){
			hexdump2(p, size[i]);
			SAFE_FREE(p);
		}	
	}
}

int main()
{
	test_random_generate();
	
	return 0;
}

