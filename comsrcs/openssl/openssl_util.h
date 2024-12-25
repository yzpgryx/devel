#ifndef __OPENSSL_UTIL_H__
#define __OPENSSL_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl/evp.h"

EVP_PKEY* sm2_from_data(unsigned char* priv, unsigned int privlen,
                        unsigned char* pub, unsigned int publen);

int xalg_sm2_sign(EVP_PKEY* pkey, const unsigned char* tbs, unsigned int tbslen,
             unsigned char* sig, size_t* siglen);

int xalg_sm2_verify(EVP_PKEY* pkey, const unsigned char* tbs, unsigned int tbslen,
               unsigned char* sig, size_t siglen);

int d2b_ECDSA_SIG(unsigned char* sig, size_t siglen,
                  unsigned char* r, int* rlen,
                  unsigned char* s, int* slen);

int b2d_ECDSA_SIG(unsigned char* r, int rlen, unsigned char* s, int slen,
                  unsigned char* sig, size_t* siglen);

int xalg_sym_encrypt(char* cipher, const unsigned char* key,
                const unsigned char* iv,
                const unsigned char* in, int inlen,
                unsigned char* out, int* outlen);

int xalg_sym_decrypt(char* cipher, const unsigned char* key,
                const unsigned char* iv,
                const unsigned char* in, int inlen,
                unsigned char* out, int* outlen);

int xalg_digest(char* algo, const unsigned char* in, size_t inlen,
                unsigned char* dgst, unsigned int* dgstlen);

#ifdef __cplusplus
}
#endif

#endif
