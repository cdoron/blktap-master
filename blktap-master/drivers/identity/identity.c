#include <string.h>
#include <stdint.h>

#include "../crypto/compat-crypto-openssl.h"
#include "../crypto/xts_aes.h"

int identity_encrypt(struct crypto_blkcipher *xts_tfm, sector_t sector,
                      uint8_t *dst_buf, uint8_t *src_buf, unsigned int nbytes) {
	if (src_buf != dst_buf) {
		memcpy(dst_buf, src_buf, nbytes);
	}
	return 0;
}

int identity_decrypt(struct crypto_blkcipher *xts_tfm, sector_t sector,
                      uint8_t *dst_buf, uint8_t *src_buf, unsigned int nbytes) {
	if (src_buf != dst_buf) {
                memcpy(dst_buf, src_buf, nbytes);
        }
        return 0;
}
