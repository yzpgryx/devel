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

int xalg_sm2_digest_sign(EVP_PKEY* pkey, const unsigned char* tbs, unsigned int tbslen,
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

int xalg_sm2_digest_verify(EVP_PKEY* pkey, const unsigned char* tbs, unsigned int tbslen,
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

static int xalg_sm2_compute_z(const unsigned char *id, size_t id_len,
                              const unsigned char* pub, size_t publen,
                              unsigned char* out, unsigned int* outlen)
{
    uint8_t default_id[] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
    uint16_t default_id_len = sizeof(default_id);
    uint8_t idbits[2] = {0};
    uint8_t sm2_params[32 * 4] = {
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
        0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
        0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
        0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
        0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
        0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
        0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
    };
    EVP_MD_CTX* mctx = NULL;
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if(!mctx) {
        return 0;
    }

    if (!out || !pub) {
        return 0;
    }

    if(id && id_len) {
        idbits[0] = (uint8_t)(id_len >> 5);
        idbits[1] = (uint8_t)(id_len << 3);
    } else {
        idbits[0] = (uint8_t)(default_id_len >> 5);
        idbits[1] = (uint8_t)(default_id_len << 3);
    }

    if(!EVP_DigestInit(mctx, EVP_get_digestbyname("SM3"))
        || !EVP_DigestUpdate(mctx, idbits, sizeof(idbits))
        || !EVP_DigestUpdate(mctx, (id && id_len) ? id : default_id,
                     (id && id_len) ? id_len : default_id_len)
        || !EVP_DigestUpdate(mctx, sm2_params, sizeof(sm2_params))
        || !EVP_DigestUpdate(mctx, pub, publen)
        || !EVP_DigestFinal(mctx, out, outlen)) {
        ret = 0;
    } else {
        ret = 1;
    }

    EVP_MD_CTX_free(mctx);
    return ret;
}

static int xalg_sm2_compute_e(const unsigned char* z, unsigned int zlen,
                          const unsigned char* m, unsigned int mlen,
                          unsigned char* e, unsigned int* elen)
{
    EVP_MD_CTX* mctx = NULL;
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if(!mctx) {
        return 0;
    }

    if(!EVP_DigestInit(mctx, EVP_get_digestbyname("SM3"))
        || !EVP_DigestUpdate(mctx, z, zlen)
        || !EVP_DigestUpdate(mctx, m, mlen)
        || !EVP_DigestFinal(mctx, e, elen)) {
        ret = 0;
    } else {
        ret = 1;
    }

    EVP_MD_CTX_free(mctx);
    return ret;
}

int xalg_sm2_pre_sign(EVP_PKEY* pkey,
                      const unsigned char* id, unsigned int idlen,
                      const unsigned char* tbs, unsigned int tbslen,
                      unsigned char* e, unsigned int* elen)
{
    unsigned char pub[65] = {0};
    size_t len = sizeof(pub);
    unsigned char z[32] = {0};
    unsigned int zlen = sizeof(z);

    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                     pub, sizeof(pub), &len);

    if(!xalg_sm2_compute_z(id, idlen, pub + 1, len - 1, z, &zlen)
        || !xalg_sm2_compute_e(z, zlen, tbs, tbslen, e, elen)) {
        return 0;
    }

    return 1;
}

int xalg_sm2_sign(EVP_PKEY* pkey, const unsigned char* e, unsigned int elen,
             unsigned char* sig, size_t* siglen)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if(!ctx) {
        goto exit;
    }

    if(EVP_PKEY_sign_init(ctx) <= 0
        || EVP_PKEY_sign(ctx, sig, siglen, e, elen) <= 0) {
        goto exit;
    }

    ret = 1;
exit:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int xalg_sm2_verify(EVP_PKEY* pkey, const unsigned char* e, unsigned int elen,
               unsigned char* sig, size_t siglen)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if(!ctx) {
        goto exit;
    }

    if(EVP_PKEY_verify_init(ctx) <= 0
        || EVP_PKEY_verify(ctx, sig, siglen, e, elen) <= 0) {
        goto exit;
    }

    ret = 1;
exit:
    EVP_PKEY_CTX_free(ctx);
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