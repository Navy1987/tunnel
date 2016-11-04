#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"
#include "aes.h"
#include "crypt.h"

#define AESKEY_LEN      32
#define AESGROUP_LEN    16
#define AESIV           "!*^$~)_+=-)(87^$#Dfhjklmnb<>,k./;KJl"


typedef void (* aes_func_t)(
	uint8_t key[AESKEY_LEN],
	const uint8_t *src,
	uint8_t *dst,
	int sz);

static void
aes_do(const uint8_t *key_text, size_t key_sz, uint8_t *data, size_t datasz, aes_func_t func)
{
	uint8_t key[AESKEY_LEN];
        if (key_sz > AESKEY_LEN) {
                sha256_context ctx;
                sha256_starts(&ctx);
                sha256_update(&ctx, key_text, key_sz);
                sha256_finish(&ctx, key);
        } else {
                memset(key, 0, sizeof(key));
                memcpy(key, key_text, key_sz);
        }
        func(key, data, data, datasz);
	return ;
}

static void
aes_encode(uint8_t key[AESKEY_LEN], const uint8_t *src, uint8_t *dst, int sz)
{
        int i;
        int group;
        int last;
        uint8_t tail[AESGROUP_LEN];
        aes_context ctx;

        group = sz / AESGROUP_LEN;
        last = sz % AESGROUP_LEN;

        //CBC
        aes_set_key(&ctx, key, AESKEY_LEN * 8);
        for (i = 0; i < group; i++) {
                int gi = i * AESGROUP_LEN;
                aes_encrypt(&ctx, &src[gi], &dst[gi]);
        }

        //OFB
        if (last) {
                if (group) {
                        memcpy(tail, &dst[(group - 1) * AESGROUP_LEN], sizeof(tail));
                } else {
                        memcpy(tail, AESIV, sizeof(tail));
                }
                aes_encrypt(&ctx, tail, tail);
                for (i = 0; i < last; i++) {
                        int gi = group * AESGROUP_LEN;
                        dst[gi + i] = src[gi + i]^tail[i];
                }
        }
        return ;
}


static void
aes_decode(uint8_t key[AESKEY_LEN], const uint8_t *src, uint8_t *dst, int sz)
{
        int i;
        int group;
        int last;
        uint8_t tail[AESGROUP_LEN];
        aes_context ctx;

        group = sz / AESGROUP_LEN;
        last = sz % AESGROUP_LEN;

        aes_set_key(&ctx, key, AESKEY_LEN * 8);
        if (last) {
                if (group) {
                        int gi = (group - 1) * AESGROUP_LEN;
                        memcpy(tail, &src[gi], sizeof(tail));
                } else {
                        memcpy(tail, AESIV, sizeof(tail));
                }
        }
        //CBC
        for (i = 0; i < group; i++) {
                int gi = i * AESGROUP_LEN;
                aes_decrypt(&ctx, &src[gi], &dst[gi]);
        }

        //OFB
        if (last) {
                aes_encrypt(&ctx, tail, tail);
                for (i = 0; i < last; i++) {
                        int gi = group * AESGROUP_LEN;
                        dst[gi + i] = src[gi + i]^tail[i];
                }
        }
        return ;
}

void crypt_encode(const uint8_t *key_text, size_t key_sz, uint8_t *data, size_t datasz)
{
	aes_do(key_text, key_sz, data, datasz, aes_encode);
}

void crypt_decode(const uint8_t *key_text, size_t key_sz, uint8_t *data, size_t datasz)
{
	aes_do(key_text, key_sz, data, datasz, aes_decode);
}



