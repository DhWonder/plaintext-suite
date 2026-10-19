/* Author: Dvash */
/* Reviewer: */

/*
 * vpn_crypto.h
 *
 * per-packet encryption, using openssl's chacha20-poly1305.
 *
 * chacha20 hides the packet; poly1305 adds a 16-byte tag that proves nobody
 * altered it in transit. together they are an AEAD - authenticated encryption -
 * and decryption FAILS rather than returning a packet if a single byte changed.
 *
 * the key is a pre-shared file, the same 32 bytes on both machines:
 *     head -c 32 /dev/urandom > vpn.key
 * a real vpn negotiates a fresh key per session instead.
 */

#ifndef VPN_CRYPTO_H
#define VPN_CRYPTO_H

#include <openssl/evp.h>    /* EVP_CIPHER_CTX */

#define VPN_KEY_BYTES   32                  /* chacha20 uses a 256-bit key */
#define VPN_NONCE_BYTES 12                  /* and a 96-bit nonce */
#define VPN_TAG_BYTES   16                  /* poly1305's authentication tag */

/* what encryption adds to every packet: nonce in front, tag on the end */
#define VPN_OVERHEAD    (VPN_NONCE_BYTES + VPN_TAG_BYTES)

#define VPN_KEY_FILE    "vpn.key"

#define VPN_CRYPTO_OK    0
#define VPN_CRYPTO_ERROR (-1)

/*
 * the key, the two halves of our nonce, and openssl's working contexts.
 *
 * salt is drawn once at startup and never changes; counter goes up by one per
 * packet. together they make a nonce this process will not repeat, and that the
 * machine at the other end is overwhelmingly unlikely to collide with.
 *
 * the contexts are created once and reused. only the nonce is rebound per
 * packet, which is the cheap path openssl documents.
 */
struct vpn_crypto
{
    unsigned char   key[VPN_KEY_BYTES];
    unsigned long   salt;
    unsigned long   counter;
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
};

/* load the 32-byte key, draw a random salt, create the openssl contexts */
int vpn_crypto_init(struct vpn_crypto *crypto, const char *key_path);

/* free the openssl contexts. safe on a partly initialised struct */
void vpn_crypto_cleanup(struct vpn_crypto *crypto);

/*
 * encrypt one packet. writes nonce, ciphertext and tag into out, and returns
 * the total (len + VPN_OVERHEAD). out needs room for len + VPN_OVERHEAD.
 */
long vpn_encrypt(struct vpn_crypto *crypto, const unsigned char *in, long len,
                 unsigned char *out);

/*
 * decrypt one packet and check its tag. returns the plain length, or
 * VPN_CRYPTO_ERROR if the datagram is too short, was altered in transit, or
 * was encrypted with a different key. nothing is written to out on failure.
 */
long vpn_decrypt(struct vpn_crypto *crypto, const unsigned char *in, long len,
                 unsigned char *out);

#endif /* VPN_CRYPTO_H */
