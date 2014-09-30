//
//  crypt.c
//  
//
//  Created by Rini Rachel on 5/2/14.
//
//

#include <stdio.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
static int setkey(struct crypto_tfm *parent, const u8 *key,
                  unsigned int keylen)
{
	struct priv *ctx = crypto_tfm_ctx(parent);
	struct crypto_cipher *child = ctx->tweak;
	u32 *flags = &parent->crt_flags;
	int err;
    
	/* key consists of keys of equal size concatenated, therefore
	 * the length must be even */
	if (keylen % 2) {
		/* tell the user why there was an error */
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}
    
	/* we need two cipher instances: one to compute the initial 'tweak'
	 * by encrypting the IV (usually the 'plain' iv) and the other
	 * one to encrypt and decrypt the data */
    
	/* tweak cipher, uses Key2 i.e. the second half of *key */
	crypto_cipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(child, crypto_tfm_get_flags(parent) &
                            CRYPTO_TFM_REQ_MASK);
	err = crypto_cipher_setkey(child, key + keylen/2, keylen/2);
	if (err)
		return err;
    
	crypto_tfm_set_flags(parent, crypto_cipher_get_flags(child) &
                         CRYPTO_TFM_RES_MASK);
    
	child = ctx->child;
    
	/* data cipher, uses Key1 i.e. the first half of *key */
	crypto_cipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(child, crypto_tfm_get_flags(parent) &
                            CRYPTO_TFM_REQ_MASK);
	err = crypto_cipher_setkey(child, key, keylen/2);
	if (err)
		return err;
    
	crypto_tfm_set_flags(parent, crypto_cipher_get_flags(child) &
                         CRYPTO_TFM_RES_MASK);
    
	return 0;
}
static int crypt(struct blkcipher_desc *d,
                 struct blkcipher_walk *w, struct priv *ctx,
                 void (*tw)(struct crypto_tfm *, u8 *, const u8 *),
                 void (*fn)(struct crypto_tfm *, u8 *, const u8 *))
{
	int err;
	unsigned int avail;
	const int bs = crypto_cipher_blocksize(ctx->child);
	struct sinfo s = {
		.tfm = crypto_cipher_tfm(ctx->child),
		.fn = fn
	};
	u8 *wsrc;
	u8 *wdst;
    
	err = blkcipher_walk_virt(d, w);
	if (!w->nbytes)
		return err;
    
	s.t = (be128 *)w->iv;
	avail = w->nbytes;
    
	wsrc = w->src.virt.addr;
	wdst = w->dst.virt.addr;
    
	/* calculate first value of T */
	tw(crypto_cipher_tfm(ctx->tweak), w->iv, w->iv);
    
	goto first;
    
	for (;;) {
		do {
			gf128mul_x_ble(s.t, s.t);
            
        first:
			xts_round(&s, wdst, wsrc);
            
			wsrc += bs;
			wdst += bs;
		} while ((avail -= bs) >= bs);
        
		err = blkcipher_walk_done(d, w, avail);
		if (!w->nbytes)
			break;
        
		avail = w->nbytes;
        
		wsrc = w->src.virt.addr;
		wdst = w->dst.virt.addr;
	}
    
	return err;
}

static int encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
                   struct scatterlist *src, unsigned int nbytes)
{
	struct priv *ctx = crypto_blkcipher_ctx(desc->tfm);
	struct blkcipher_walk w;
    
	blkcipher_walk_init(&w, dst, src, nbytes);
	return crypt(desc, &w, ctx, crypto_cipher_alg(ctx->tweak)->cia_encrypt,
                 crypto_cipher_alg(ctx->child)->cia_encrypt);
}

static int decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
                   struct scatterlist *src, unsigned int nbytes)
{
	struct priv *ctx = crypto_blkcipher_ctx(desc->tfm);
	struct blkcipher_walk w;
    
	blkcipher_walk_init(&w, dst, src, nbytes);
	return crypt(desc, &w, ctx, crypto_cipher_alg(ctx->tweak)->cia_encrypt,
                 crypto_cipher_alg(ctx->child)->cia_decrypt);
}