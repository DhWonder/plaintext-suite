/* Author: Dvash */
/* Reviewer: */

/*
 * vpn_crypto.c
 *
 * chacha20-poly1305 through openssl's EVP interface.
 *
 * this file used to contain a hand-written chacha20. it was replaced with the
 * library version: the algorithm is identical, but openssl's is audited,
 * constant-time on every platform, and comes with poly1305 authentication for
 * almost no extra code.
 */

#include <stdio.h>          /* fopen, fread, fprintf, perror */
#include <string.h>         /* memset */
#include <stdlib.h>         /* size_t */

#include <openssl/evp.h>    /* EVP_* */

#include "vpn_crypto.h"

#define RANDOM_DEV "/dev/urandom"
#define MASK32     0xFFFFFFFFUL

/* read four bytes as one 32-bit word, least significant byte first */
static unsigned long load32(const unsigned char *p)
{
    return  (unsigned long)p[0]
         | ((unsigned long)p[1] << 8)
         | ((unsigned long)p[2] << 16)
         | ((unsigned long)p[3] << 24);
}

/* and the same the other way */
static void store32(unsigned char *p, unsigned long v)
{
    p[0] = (unsigned char)( v        & 0xFF);
    p[1] = (unsigned char)((v >> 8)  & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

/* read exactly n bytes from a file, or fail. used for the key and the salt */
static int read_exactly(const char *path, unsigned char *buf, size_t n)
{
    FILE *fp = fopen(path, "rb");
    size_t got = 0;

    if (NULL == fp)
    {
        perror(path);
        return VPN_CRYPTO_ERROR;
    }

    got = fread(buf, 1, n, fp);
    fclose(fp);

    if (got != n)
    {
        fprintf(stderr, "%s: wanted %lu bytes, got %lu\n", path,
                (unsigned long)n, (unsigned long)got);
        return VPN_CRYPTO_ERROR;
    }

    return VPN_CRYPTO_OK;
}

int vpn_crypto_init(struct vpn_crypto *crypto, const char *key_path)
{
    unsigned char salt_bytes[4];

    if (NULL == crypto || NULL == key_path)
    {
        return VPN_CRYPTO_ERROR;
    }

    memset(crypto, 0, sizeof(*crypto));

    if (VPN_CRYPTO_OK != read_exactly(key_path, crypto->key, VPN_KEY_BYTES))
    {
        fprintf(stderr, "  make a key with:  head -c %d /dev/urandom > %s\n"
                        "  and copy the SAME file to the other machine\n",
                VPN_KEY_BYTES, key_path);
        return VPN_CRYPTO_ERROR;
    }

    /* the salt keeps this process's nonces clear of the other side's */
    if (VPN_CRYPTO_OK != read_exactly(RANDOM_DEV, salt_bytes, 4))
    {
        return VPN_CRYPTO_ERROR;
    }

    crypto->salt = load32(salt_bytes);
    crypto->counter = 0;

    crypto->enc = EVP_CIPHER_CTX_new();
    crypto->dec = EVP_CIPHER_CTX_new();

    if (NULL == crypto->enc || NULL == crypto->dec)
    {
        fprintf(stderr, "vpn_crypto_init: openssl would not give us a context\n");
        vpn_crypto_cleanup(crypto);
        return VPN_CRYPTO_ERROR;
    }

    /* bind the algorithm and the key once. from here on only the nonce
       changes, which is the cheap path openssl documents */
    if (1 != EVP_EncryptInit_ex(crypto->enc, EVP_chacha20_poly1305(), NULL,
                                crypto->key, NULL) ||
        1 != EVP_DecryptInit_ex(crypto->dec, EVP_chacha20_poly1305(), NULL,
                                crypto->key, NULL))
    {
        fprintf(stderr, "vpn_crypto_init: openssl rejected the key\n");
        vpn_crypto_cleanup(crypto);
        return VPN_CRYPTO_ERROR;
    }

    return VPN_CRYPTO_OK;
}

void vpn_crypto_cleanup(struct vpn_crypto *crypto)
{
    if (NULL == crypto)
    {
        return;
    }

    if (NULL != crypto->enc)
    {
        EVP_CIPHER_CTX_free(crypto->enc);
        crypto->enc = NULL;
    }

    if (NULL != crypto->dec)
    {
        EVP_CIPHER_CTX_free(crypto->dec);
        crypto->dec = NULL;
    }
}

long vpn_encrypt(struct vpn_crypto *crypto, const unsigned char *in, long len,
                 unsigned char *out)
{
    int body = 0;
    int rest = 0;

    /* the nonce is built straight into the front of the outgoing datagram.
       it travels in the clear - a nonce is not a secret, it only has to be
       unique for the lifetime of the key */
    memset(out, 0, VPN_NONCE_BYTES);
    store32(out, crypto->salt);
    store32(out + 8, crypto->counter);

    crypto->counter = (crypto->counter + 1) & MASK32;

    /* rebind just the nonce, then encrypt the packet after it */
    if (1 != EVP_EncryptInit_ex(crypto->enc, NULL, NULL, NULL, out) ||
        1 != EVP_EncryptUpdate(crypto->enc, out + VPN_NONCE_BYTES, &body,
                               in, (int)len) ||
        1 != EVP_EncryptFinal_ex(crypto->enc, out + VPN_NONCE_BYTES + body,
                                 &rest))
    {
        return VPN_CRYPTO_ERROR;
    }

    /* poly1305's tag goes on the end, computed over the ciphertext */
    if (1 != EVP_CIPHER_CTX_ctrl(crypto->enc, EVP_CTRL_AEAD_GET_TAG,
                                 VPN_TAG_BYTES,
                                 out + VPN_NONCE_BYTES + body + rest))
    {
        return VPN_CRYPTO_ERROR;
    }

    return (long)(VPN_NONCE_BYTES + body + rest + VPN_TAG_BYTES);
}

long vpn_decrypt(struct vpn_crypto *crypto, const unsigned char *in, long len,
                 unsigned char *out)
{
    long payload = len - VPN_OVERHEAD;
    int body = 0;
    int rest = 0;

    if (payload < 0)
    {
        return VPN_CRYPTO_ERROR;    /* too short to hold a nonce and a tag */
    }

    /* the sender's nonce is sitting at the front of what arrived */
    if (1 != EVP_DecryptInit_ex(crypto->dec, NULL, NULL, NULL, in) ||
        1 != EVP_DecryptUpdate(crypto->dec, out, &body,
                               in + VPN_NONCE_BYTES, (int)payload))
    {
        return VPN_CRYPTO_ERROR;
    }

    /* hand openssl the tag that came with the packet */
    if (1 != EVP_CIPHER_CTX_ctrl(crypto->dec, EVP_CTRL_AEAD_SET_TAG,
                                 VPN_TAG_BYTES,
                                 (void *)(in + VPN_NONCE_BYTES + payload)))
    {
        return VPN_CRYPTO_ERROR;
    }

    /*
     * this is the check the old hand-written version could not make. it fails
     * if any byte of the packet was altered in transit, or if the sender used
     * a different key - and the plaintext is discarded rather than handed on.
     */
    if (1 != EVP_DecryptFinal_ex(crypto->dec, out + body, &rest))
    {
        return VPN_CRYPTO_ERROR;
    }

    return (long)(body + rest);
}
