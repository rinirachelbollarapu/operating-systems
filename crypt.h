//
//  crypt.h
//  
//
//  Created by Rini Rachel on 5/2/14.
//
//

#ifndef _crypt_h
#define _crypt_h
static int setkey(struct crypto_tfm *parent, const u8 *key,
                  unsigned int keylen);
static int crypt(struct blkcipher_desc *d,
                 struct blkcipher_walk *w, struct priv *ctx,
                 void (*tw)(struct crypto_tfm *, u8 *, const u8 *),
                 void (*fn)(struct crypto_tfm *, u8 *, const u8 *));
static int encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
                   struct scatterlist *src, unsigned int nbytes);
static int decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
                   struct scatterlist *src, unsigned int nbytes);


#endif
