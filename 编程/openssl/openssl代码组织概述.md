
## 说明
- 上层框架都包含在 evp 目录下，其他目录文件为具体应用类型底层实现文件，其中对 evp 目录而言：
  ```shell
    e_...         // EVP_CIPHER | 底层对称加密类型实现的封装
    p_...         // EVP_PKEY   | 底层非对称加密类型的封装
    m_...         // EVP_MD_CTX | 散列界面层封装
    evp_...       // EVP_CIPHER_CTX | 对称加解密界面层封装
    pmeth_...     // EVP_PKEY_CTX | 非对称加解密界面层封装
  ```
- 以下 3 个部分，所有的界面层接口函数可在 evp.h 中查看；
- 方法层连接底层与界面层，方法层中的操作以全局结构的形式提供给上层；
- 对称加解密部分中，界面层又分为对分组密码和流密码的操作；

## 非对称加解密部分
- 主要文件及说明
  ```shell
    pmeth_lib.c           // 界面层 | EVP_PKEY_CTX | 创建初始化/释放/拷贝/控制/其他非常用操作
    pmeth_fn.c            // 界面层 | EVP_PKEY_CTX | 签名/验签/非对称加解密
    pmeth_gn.c            // 界面层 | EVP_PKEY_CTX | 密钥对生成/其他非常用操作
      rsa_pmeth.c         // 方法层 | RSA_PKEY_CTX | rsa 分支 
        rsa_ameth.c       // 基础层 | RSA ...
        rsa_asn1.c
        rsa_chk.c
        ...
      ec_pmeth.c          // 方法层 | EC_PKEY_CTX  | ecc 分支 
        ec_ameth.c        // 基础层 | EC_KEY ...
        ec_asn1.c
        ec_check.c
        ...
      ...
  ```
- 其中: RSA_PKEY_CTX 或 EC_PKEY_CTX 通过 EVP_PKEY 进行封装，而后者是 EVP_PKEY_CTX 的结构体成员。

## 对称加解密部分
- 主要文件及说明
  ```shell
  evp_enc.c             // 界面层 | EVP_CIPHER_CTX | 创建/初始化/参数初始化/加解密更新/加解密收尾/清扫
    e_aes.c             // 方法层 | EVP_AES_KEY    | aes 分支 （包含有对 GCM XTS CCM 模式的实现）
      aes.h             // 基础层 | AES_KEY ...
      aes_cbc.c
      ...
    e_des3.c            // 方法层 | DES_EDE_KEY    | des 分支
      des.h             // 基础层 | DES_key_schedule ...
      des_enc.c
      ...
    e_camellia.c        // 方法层 | EVP_CAMELLIA_KEY | camellia 分支
      camellia.h        // 基础层 | CAMELLIA_KEY ...
      camellia.c
      ...
    ...
  ```
- 其中: EVP_AES_KEY 或 DES_EDE_KEY 或 EVP_CAMELLIA_KEY 通过 EVP_CIPHER 进行封装，而后者是 EVP_CIPHER_CTX 的结构体成员。

## 散列部分
- 主要文件及说明
  ```shell
    digest.c              // 界面层 | EVP_MD_CTX | 创建/初始化/更新/收尾/拷贝/清扫
      m_md5.c             // 方法层 | EVP_MD_CTX | md5 分支
        md5.h             // 基础层 | MD5_CTX ...
        md5.c
        ...
      m_sha.c             // 方法层 | EVP_MD_CTX | sha 分支
        sha.h             // 基础层 | SHA512_CTX ...
        sha512.c
        ...
      ...
  ```
- 其中: MD5_CTX 或 SHA512_CTX 通过 EVP_MD 进行封装，而后者是 EVP_MD_CTX 的结构体成员。
- 其中: 散列过程中可能会用到非对称加解密，所以 EVP_MD_CTX 的成员有 EVP_PKEY_CTX 。

## 补充说明
- 仅就 openssl 而言，只需要封装 EVP_PKEY, EVP_PKEY_CTX, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MD, EVP_MD_CTX 即可。
- 一般地，其需要向用户提供的接口也可以从 evp.h 中选择即可。

## 其他重要的文件
- 如下:
  ```shell
    obj_mac.h         // nid name ...
        names.c
    p_lib.c
  ```