#include "openssl/types.h"
#include "openssl/param_build.h"
#include "openssl_util.h"
#include "openssl/encoder.h"
#include "openssl/core_names.h"
#include "openssl/ec.h"
#include "util.h"

EVP_PKEY* sm2_from_data(unsigned char* d, unsigned int dlen,
    unsigned char* pub, unsigned int publen)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY* pkey = NULL;
    BIGNUM *priv = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;

    priv = BN_bin2bn(d, dlen, NULL);

    param_bld = OSSL_PARAM_BLD_new();
    if (priv != NULL && param_bld != NULL
        && OSSL_PARAM_BLD_push_utf8_string(param_bld, "group",
                                           "SM2", 0)
        && OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv)
        && OSSL_PARAM_BLD_push_octet_string(param_bld, "pub",
                                            pub, publen))
        params = OSSL_PARAM_BLD_to_param(param_bld);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (ctx == NULL
        || params == NULL
        || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
    }

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_free(priv);

    return pkey;
}

int xalg_sm2_sign(EVP_PKEY* pkey, const unsigned char* tbs, unsigned int tbslen,
    unsigned char* sig, size_t* siglen)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX* mctx = NULL;
    size_t len = 0;
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if(!mctx) {
        return 0;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if(!ctx) {
        goto exit;
    }

    EVP_MD_CTX_set_pkey_ctx(mctx, ctx);
    if(EVP_DigestSignInit_ex(mctx, NULL, "SM3", NULL, NULL, pkey, NULL) <= 0
        || EVP_DigestSign(mctx, NULL, &len, tbs, tbslen) <= 0) {
        goto exit;
    }
    
    if(len > *siglen) {
        goto exit;
    }

    if(EVP_DigestSign(mctx, sig, siglen, tbs, tbslen) <= 0) {
        goto exit;
    }

exit:
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_CTX_free(mctx);

    return ret;
}

int xalg_sm2_verify(EVP_PKEY* pkey, const unsigned char* tbs, unsigned int tbslen,
               unsigned char* sig, size_t siglen)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX* mctx = NULL;
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if(!mctx) {
        return 0;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if(!ctx) {
        goto exit;
    }

    EVP_MD_CTX_set_pkey_ctx(mctx, ctx);
    if(EVP_DigestVerifyInit_ex(mctx, NULL, "SM3", NULL, NULL, pkey, NULL) <= 0
        || EVP_DigestVerify(mctx, sig, siglen, tbs, tbslen) <= 0) {
        goto exit;
    }

    ret = 1;

exit:
    EVP_PKEY_CTX_free(ctx);
    EVP_MD_CTX_free(mctx);

    return ret;
}

int d2b_ECDSA_SIG(unsigned char* sig, size_t siglen,
                  unsigned char* r, int* rlen,
                  unsigned char* s, int* slen)
{
    const unsigned char* p = sig;
    ECDSA_SIG* signature = NULL;
    const BIGNUM* rr = NULL, *ss = NULL;

    signature = d2i_ECDSA_SIG(NULL, &p, siglen);
    if(!signature) {
        return 0;
    }

    ECDSA_SIG_get0(signature, &rr, &ss);
    if(rr && r && rlen) {
        BN_bn2binpad(rr, r, *rlen);
    }

    if(ss && s && slen) {
        BN_bn2binpad(ss, s, *slen);
    }

    ECDSA_SIG_free(signature);
    return 1;
}

int b2d_ECDSA_SIG(unsigned char* r, int rlen, unsigned char* s, int slen,
                  unsigned char* sig, size_t* siglen)
{
    ECDSA_SIG* signature = NULL;
    BIGNUM* rr = NULL, *ss = NULL;
    unsigned char* der = NULL;
    int ret = 0, derlen = 0;

    rr = BN_bin2bn(r, rlen, NULL);
    ss = BN_bin2bn(s, slen, NULL);
    signature = ECDSA_SIG_new();
    if(!signature) {
        goto exit;
    }

    ECDSA_SIG_set0(signature, rr, ss);
    if(!rr || !ss) {
        goto exit;
    }

    derlen = i2d_ECDSA_SIG(signature, NULL);
    if(derlen > *siglen) {
        goto exit;
    }

    *siglen = i2d_ECDSA_SIG(signature, &der);
    memcpy(sig, der, *siglen);

    ret = 1;
exit:
    free(der);
    ECDSA_SIG_free(signature);
    return ret;
}

static int sym_crypt(char* algo, const unsigned char* key,
                const unsigned char* iv,
                const unsigned char* in, int inlen,
                unsigned char* out, int* outlen,
                int enc)
{
    int ret = 0, tlen = 0, t2len = 0;
    const EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        return 0;
    }

    cipher = EVP_get_cipherbyname(algo);
    if(!cipher) {
        goto exit;
    }

    if(EVP_CipherInit(ctx, cipher, key, iv, enc) <= 0
        || EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0
        || EVP_CipherUpdate(ctx, out, &tlen, in, inlen) <= 0
        || EVP_CipherFinal(ctx, out + tlen, &t2len) <= 0) {
        *outlen = 0;
        goto exit;
    }

    *outlen = tlen + t2len;
    ret = 1;
    EVP_CIPHER_CTX_free(ctx);
exit:
    return ret;
}

int xalg_sym_encrypt(char* algo, const unsigned char* key,
                const unsigned char* iv,
                const unsigned char* in, int inlen,
                unsigned char* out, int* outlen)
{
    return sym_crypt(algo, key, iv, in, inlen, out, outlen, 1);
}

int xalg_sym_decrypt(char* algo, const unsigned char* key,
                const unsigned char* iv,
                const unsigned char* in, int inlen,
                unsigned char* out, int* outlen)
{
    return sym_crypt(algo, key, iv, in, inlen, out, outlen, 0);
}

int xalg_digest(char* algo, const unsigned char* in, size_t inlen,
                unsigned char* dgst, unsigned int* dgstlen)
{
    return EVP_Digest(in, inlen, dgst, dgstlen, EVP_get_digestbyname(algo), NULL);
}