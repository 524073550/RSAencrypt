//
// Created by StephenLau on 2019/4/11.
//
#include <jni.h>
#include <string>
#include "encrypt.h"
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>

extern "C" JNIEXPORT jbyteArray JNICALL
Java_lau_stephen_rsaencrypt_EncryptUtils_encodeByRSAPubKey(JNIEnv *env, jclass type,
                                                           jbyteArray src_) {
    std::string keys = "-----BEGIN PUBLIC KEY-----\n"
                       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwm/vZlgdvA/s3o+Epq2B\n"
                       "TF9Pk1goY4+wji1fjkmePasZkt12Rx0A0qXuzBfe8K4Y1uf/sKD1XHeXtvPol5TF\n"
                       "ZKq6dEQpd3PsweFMFGYfZbA5IdwEQWXFJqJSpru/jXENCanUARVV5Au0fjaMw71x\n"
                       "dGbHQ7gNdxln9xeoPkyCLBuWor5B3U47NFGEz8ZMELCib0+9bPtzIVuBYA5BsT9A\n"
                       "WgHZpuRZRgQ2r3a0ehe7gO1H+SKrLStVzUZ7EUW4PBM4IhIrR+BfORHi4PgD+4rZ\n"
                       "IuMzg99Y20ytaHIm6tw6+dvt3gSY2q2VWITCVE2dtH167R/AR+mJDFhp89Ss1sGE\n"
                       "wQIDAQAB\n"
                       "-----END PUBLIC KEY-----";

    jbyte *src = env->GetByteArrayElements(src_, NULL);

    jsize src_Len = env->GetArrayLength(src_);

    int encryptedValueSize = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;

    //BIO_new_mem_buf() creates a memory BIO using len bytes of data at buf,
    // if len is -1 then the buf is assumed to be nul terminated and its length is determined by strlen.
    BIO *keyBio = BIO_new_mem_buf((void *) keys.c_str(), -1);
    //The RSA structure consists of several BIGNUM components.
    // It can contain public as well as private RSA keys:
    RSA *publicKey = PEM_read_bio_RSA_PUBKEY(keyBio, NULL, NULL, NULL);
    //释放BIO
    BIO_free_all(keyBio);

    //RSA_size returns the RSA modulus size in bytes.
    // It can be used to determine how much memory must be allocated for an RSA encrypted value.
    int flen = RSA_size(publicKey);

    //复制src到srcOrigin
    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);
    //每次加密后的长度
    unsigned char *encryptedValue = (unsigned char *) malloc(flen);

    desText_len = flen * (src_Len / (flen - 11) + 1);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    //对数据进行公钥加密运算
    //对于1024bit，2048应该为256
    //RSA_PKCS1_PADDING 最大加密长度 为 128 -11
    //RSA_NO_PADDING 最大加密长度为  128
    //rsa_size = rsa_size - RSA_PKCS1_PADDING_SIZE;
    for (int i = 0; i <= src_Len / (flen - 11); i++) {
        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
        if (src_flen == 0) {
            break;
        }
        //重置encryptedValue
        memset(encryptedValue, 0, flen);
        //encrypt srcOrigin + src_offset到encryptedValue
        //returns the size of the encrypted data
        encryptedValueSize = RSA_public_encrypt(src_flen, srcOrigin + src_offset, encryptedValue,
                                                publicKey, RSA_PKCS1_PADDING);
        if (encryptedValueSize == -1) {
            RSA_free(publicKey);
            CRYPTO_cleanup_all_ex_data();
            env->ReleaseByteArrayElements(src_, src, 0);
            free(srcOrigin);
            free(encryptedValue);
            free(desText);

            return NULL;
        }
        //复制encryptedValue到desText + cipherText_offset
        memcpy(desText + cipherText_offset, encryptedValue, encryptedValueSize);

        cipherText_offset += encryptedValueSize;
        src_offset += src_flen;
    }

    RSA_free(publicKey);
    //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
    CRYPTO_cleanup_all_ex_data();

    //从jni释放数据指针
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);

    //在堆中分配ByteArray数组对象成功，将拷贝数据到数组中
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
    //释放内存
    free(srcOrigin);
    free(encryptedValue);
    free(desText);

    return cipher;
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_lau_stephen_rsaencrypt_EncryptUtils_decodeByRSAPrivateKey(JNIEnv *env, jclass type,
                                                               jbyteArray src_) {
    std::string keys = "-----BEGIN RSA PRIVATE KEY-----\n"
                       "MIIEpQIBAAKCAQEAwm/vZlgdvA/s3o+Epq2BTF9Pk1goY4+wji1fjkmePasZkt12\n"
                       "Rx0A0qXuzBfe8K4Y1uf/sKD1XHeXtvPol5TFZKq6dEQpd3PsweFMFGYfZbA5IdwE\n"
                       "QWXFJqJSpru/jXENCanUARVV5Au0fjaMw71xdGbHQ7gNdxln9xeoPkyCLBuWor5B\n"
                       "3U47NFGEz8ZMELCib0+9bPtzIVuBYA5BsT9AWgHZpuRZRgQ2r3a0ehe7gO1H+SKr\n"
                       "LStVzUZ7EUW4PBM4IhIrR+BfORHi4PgD+4rZIuMzg99Y20ytaHIm6tw6+dvt3gSY\n"
                       "2q2VWITCVE2dtH167R/AR+mJDFhp89Ss1sGEwQIDAQABAoIBAQCo+dRo8i0tMf3d\n"
                       "0YYrwF+8+pvSZmv7UnXSqdYAdzQhTeAUxYgz9x2u82vbTOd/7R1DLy4D125EpN5h\n"
                       "rgk2KqF9ge42esI6wLFCMUUH+VRR8FtGdMnx97rlf24q3sFy74uwGTpYkq0pWY7L\n"
                       "nSaqOaouyd9kl8CD/71dfN7G/YCnSPLFqyup7mrGZT/uyDuJdJ3hh3dSGup6yid2\n"
                       "3nQwwYDYAVobJkiV0lh0IgKabKW1eGOI1Bwsek6pnTJe+BmXQMnZYcyYE/Wjw7Yk\n"
                       "76z4Y5zcxviNK82RnKfUhxOSR3GbD+769Xlwc0xcEaR5mFcp9SmPFf8wLTmEZsCq\n"
                       "MUxvrdstAoGBAOJrAyKcEdHvLKfaGvjBDLM8CQgFhl4wKLPH9kgUfTShVxIjr5oJ\n"
                       "HXc7ub4pPQd+OXG7D5pbQhmMQw7JukjKX/ogFmFEC07dRkITgRn9iD6sAiOztH0r\n"
                       "jllnyDsNGk2orlMuWAbalk7JhDXX0m930AlUNAwpWC7c4Po0rVSjotmnAoGBANvX\n"
                       "Q6m0/C/JiHT35d0tIPfzcuW+LbKX4mdlcmaUCPYwaDYRe2EO8UzkPqtLysTB79L7\n"
                       "mAVsTfL+c2tcnlnwhehOGYSGugdyWT/9vmPwkXNjt/pgfjuhUHE9g7OqnIR7r/Pb\n"
                       "zBqXq2Ed2Jw4raUBcsjac7pP+0Oa94dCVXsHoatXAoGBAKpQuREFuVnjwgGZTQSl\n"
                       "ovoIRPrlvQeIznU+C4J49x3p52dbtLH3/VQ9dyEWQDQsvOVSQxBnaTdyjNbI4/nx\n"
                       "UXUDQhJ0btUqGbmGlmyIjD4ogYt9mF03sGKMcNAKsSiNpGQpzkmJj9tANtWRvVfg\n"
                       "FnuN/YDQcOb/e7R6f4/Vb6CtAoGAf1XIU1wJVoSdDWMpOVsSZYwVWQ022uMuuEUC\n"
                       "ZngIWNDhC7BEjothKPBrfDyCTkUm7EXeYAXDgKPxppYXAnFWnp/eF+0Rg46wM2h+\n"
                       "BtUo6nUv805Az7k4Jt9CkaaY0gPyfoUpS53eHnpzJMmPiqu0GLKvpZL+LsJr7WR2\n"
                       "rrRU6DECgYEAnHDyHhHrarv7xVjw91Zxj5/uBgeAL/R6vx2BVfX6Ib6ZjOZ3jxu6\n"
                       "tnf8GAmQWWsvRCn5kmAC3Y36MgpCxe7OVUkIcIePcCE4Yv3T4fFWD6r17QzQKYMh\n"
                       "iAUkM8uODGPWt8BxFLSYICp2SnF8gCs0/Ob+PiAfC80LhnBl4wB4+gM=\n"
                       "-----END RSA PRIVATE KEY-----";

    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, plaintext_offset = 0, descText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    keybio = BIO_new_mem_buf((void *) keys.c_str(), -1);
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    descText_len = (flen - 11) * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(descText_len);
    memset(desText, 0, descText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

    for (int i = 0; i <= src_Len / flen; i++) {
        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
        if (src_flen == 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_private_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa,
                                  RSA_PKCS1_PADDING);
        if (ret == -1) {
            RSA_free(rsa);
            CRYPTO_cleanup_all_ex_data();
            env->ReleaseByteArrayElements(src_, src, 0);
            free(srcOrigin);
            free(plaintext);
            free(desText);

            return NULL;
        }
        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();

    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
    free(srcOrigin);
    free(plaintext);
    free(desText);

    return cipher;
}
