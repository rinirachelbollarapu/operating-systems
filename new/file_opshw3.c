#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <asm/scatterlist.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/string.h>
#include "internal.h"
#include "testmgr.h"
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <crypto/internal/compress.h>
#include <linux/zlib.h>
#include <crypto/hash.h>
#include "tcrypt.h"

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/rng.h>

#include "internal.h"
#include "xjob.h"

#define MAX_BLK_SIZE (64*1024*1024)
#define MIN_BLK_SIZE (16)

#define DATA_SIZE       16
#define ENCRYPT_ALGO "ctr(aes)"

struct tcrypt_result {

struct completion completion;

int err;

};



static void tcrypt_complete(struct crypto_async_request *req, int err)

{

struct tcrypt_result *res = req->data;

    

if (err == -EINPROGRESS)

return;

    

res->err = err;

complete(&res->completion);

}

static void

hexdump(unsigned char *buf, unsigned int len)

{

    printk("\nshow hexdump\n");

    while (len--)

        printk("%02x", *buf++);

    

    printk("\n");

}

int aes_encrypt( char *key1, int key_len, char *clear_text, char **cipher_text, size_t size) {

    
printk("\n------------3\n");
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);

        int rc;

    printk("\n------------4\n");

    if(IS_ERR(tfm)) {

        printk("aes_encrypt: cannot allocate cipher\n");

        rc = PTR_ERR(tfm);

        return rc;

        

    }
printk("\n------------5\n");

    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
    

    

    unsigned char *key;
    key = kmalloc(key_len,GFP_KERNEL);

    int j=0;

    for(j=0;j<key_len;j++){

        key[j] = key1[j];

        printk("\n%x",key[j]);

    }

    

    printk("\n------------6\n");

    rc = crypto_blkcipher_setkey(tfm, key, key_len);

    if(rc) {

        printk("aes_encrypt: cannot set key\n");

        goto out;

    }

    struct scatterlist *src;

    struct scatterlist *dst;

    u32 npages = MAX_BLK_SIZE/PAGE_SIZE;

    
printk("\n------------7\n");
    src = kmalloc(npages*sizeof(struct scatterlist), __GFP_ZERO|GFP_KERNEL);

    if (!src) {

        printk("taes ERROR: failed to alloc src\n");

        return;

    }

    dst = kmalloc(npages*sizeof(struct scatterlist), __GFP_ZERO|GFP_KERNEL);

    if (!dst) {

        printk("taes ERROR: failed to alloc dst\n");

        kfree(src);

        return;

    }

    

    sg_init_table(src, npages);

    int i;

    for (i=0; i<1; i++) {

        if (!clear_text) {

            printk("taes ERROR: alloc free page error\n");

            goto out;

        }

        printk("\n------------8\n");

        sg_set_buf(src+i, clear_text, PAGE_SIZE);

        

        

        

        *cipher_text = kmalloc(size,GFP_KERNEL);

        

        if (!*cipher_text) {

            printk("taes ERROR: alloc free page error\n");

            goto out;

        }

        sg_set_buf(dst+i, *cipher_text, PAGE_SIZE);

        

    }
    printk("\n------------9\n");

    rc = crypto_blkcipher_encrypt(&desc, dst, src, size);

    printk("\n------------9.5\n");

    crypto_free_blkcipher(tfm);

    

    if(rc<0) {

        pr_err("aes_encrypt: encryption failed %d\n", rc);

        goto out;

    }

    rc=0;

    

out:
    kfree(key);
    kfree(src);

    kfree(dst);

    return rc;

}

int encrypt_file(char *filename,int algo,char *output_file, char* key1,int key_len){

    

    
    printk("\n------------1\n");
    

    mm_segment_t oldfs;

    struct file *outfile = NULL;

    outfile = filp_open(output_file,O_CREAT|O_WRONLY,0);

    

    struct file *filp = NULL;

    filp = filp_open(filename,O_RDONLY,0);

    oldfs = get_fs();

set_fs(KERNEL_DS);

    

if(IS_ERR(filp)){

return -(PTR_ERR(filp));

}

    

    if(!filp || IS_ERR(filp)){

        return -EPERM;

    }

    

    if(!filp->f_op->read){

        return -ENOENT;

    }

    

    int rc;

    

    

    char * buf;

    

    u32 npages = MAX_BLK_SIZE/PAGE_SIZE;

    

    

    while(1){

int bytes_to_write;

        buf = (char*)kmalloc(4096,GFP_KERNEL);

        

bytes_to_write=vfs_read(filp,buf,4086,&filp->f_pos);

        

if(IS_ERR(bytes_to_write) || bytes_to_write < 0){

            rc = bytes_to_write;

            kfree(buf);

            goto out;

}

        buf[bytes_to_write+1]='\0';

        int len = strlen(buf);

        printk("\n------------2\n");

        if(bytes_to_write>0){

            

            int len = strlen(buf);

            

            char *cipher_text ;

            aes_encrypt(key1, key_len,buf , &cipher_text,  bytes_to_write);

            
printk("\n------------10\n");
            

            

int write_bytes = vfs_write(outfile,cipher_text,bytes_to_write,&outfile->f_pos);

            printk("\n------------11\n");

if(IS_ERR(write_bytes) ){

                

                goto out;

}

            

            

            rc=0;

        }

        

        else{

            kfree(buf);

            

            break;

        }

    freebuf:

        kfree(buf);

        

    }

    return 0;

    

out:

    set_fs(oldfs);

    if(filp!=NULL && !IS_ERR(filp)){

        filp_close(filp,NULL);

    }

    if(outfile!=NULL && !IS_ERR(outfile)){

        filp_close(outfile,NULL);

    }

    return rc;

}


int aes_decrypt(char *key1, int key_len,  char *cipher_text, char **clear_text, size_t size) {

    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);

    

    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};

    int rc;

    

    if(IS_ERR(tfm)) {

        printk("aes_decrypt: cannot allocate cipher\n");

        rc = PTR_ERR(tfm);

        return rc;

        

    }

    

    unsigned char key[key_len];

    int j=0;

    for(j=0;j<key_len;j++){

        key[j] = key1[j];

        printk("\n%x",key[j]);

    }

    

    rc = crypto_blkcipher_setkey(tfm, key, sizeof(key));

    if(rc) {

        printk("aes_decrypt: cannot set key\n");

        goto out;

    }

    

    struct scatterlist *src;

    struct scatterlist *dst;

    u32 npages = MAX_BLK_SIZE/PAGE_SIZE;

    

    src = kmalloc(npages*sizeof(struct scatterlist), __GFP_ZERO|GFP_KERNEL);

    if (!src) {

        printk("taes ERROR: failed to alloc src\n");

        return;

    }

    dst = kmalloc(npages*sizeof(struct scatterlist), __GFP_ZERO|GFP_KERNEL);

    if (!dst) {

        printk("taes ERROR: failed to alloc dst\n");

        kfree(src);

        return;

    }

    sg_init_table(src, npages);

    int i;

    for (i=0; i<1; i++) {

        *clear_text = (char*)kmalloc(size,GFP_KERNEL);

        if (!*clear_text) {

            printk("taes ERROR: alloc free page error\n");

            goto  out;

        }

        

        sg_set_buf(src+i, *clear_text, PAGE_SIZE);

        if (!cipher_text) {

            printk("taes ERROR: alloc free page error\n");

            goto out;

        }

        

        sg_set_buf(dst+i, cipher_text, PAGE_SIZE);

    }

    rc = crypto_blkcipher_decrypt(&desc, src, dst, size);

    

    crypto_free_blkcipher(tfm);

    if(rc<0) {

        pr_err("aes_decrypt: decryption failed %d\n", rc);

        goto out;

    }

    

    rc=0;

    

    

out:

    kfree(src);

    kfree(dst);

    return rc;

}

int decrypt_file(char *filename,int algo,char *output_file, char* key1,int key_len){

    

    

    

    mm_segment_t oldfs;

    struct file *outfile = NULL;

    outfile = filp_open(output_file,O_CREAT|O_WRONLY,0);

    

    struct file *filp = NULL;

    filp = filp_open(filename,O_RDONLY,0);

    oldfs = get_fs();

set_fs(KERNEL_DS);

    

if(IS_ERR(filp)){

return -(PTR_ERR(filp));

}

    

    if(!filp || IS_ERR(filp)){

        return -EPERM;

    }

    

    if(!filp->f_op->read){

        return -ENOENT;

    }

    

    int rc;

    

    

    char * buf;

    

    u32 npages = MAX_BLK_SIZE/PAGE_SIZE;

    

    

    while(1){

int bytes_to_write;

        buf = (char*)kmalloc(4096,GFP_KERNEL);

bytes_to_write=vfs_read(filp,buf,4086,&filp->f_pos);

if(IS_ERR(bytes_to_write) || bytes_to_write < 0){

            rc = bytes_to_write;

            kfree(buf);

            goto out;

}

        buf[bytes_to_write+1]='\0';

        

        if(bytes_to_write>0){

            

            

            

            int len = strlen(buf);

            

            char *clear_text ;

            aes_decrypt(key1, key_len,buf , &clear_text,  bytes_to_write);

            

            

            

            

int write_bytes = vfs_write(outfile,clear_text,bytes_to_write,&outfile->f_pos);

            

if(IS_ERR(write_bytes) ){

                

                goto out;

                

}

            

            

            rc=0;

        }

        

        else{

            kfree(buf);

            break;

        }

    freebuf:

        kfree(buf);

        

    }

    return 0;

    

out:

    set_fs(oldfs);

    if(filp!=NULL && !IS_ERR(filp)){

        filp_close(filp,NULL);

    }

    if(outfile!=NULL && !IS_ERR(outfile)){

        filp_close(outfile,NULL);

    }

    return rc;

}


/*------------------------------------------------*/

int compress_file(char *filename,int algo,char* output_file){

    mm_segment_t oldfs;
	char* algoName = NULL;
	if(algo == 0)
	{	
		algoName = kstrdup("deflate",GFP_KERNEL);
	}
	else if(algo == 1)
	{
		algoName = kstrdup("lzo", GFP_KERNEL);
	}
	else
	{
		return -EINVAL;
	}
    struct file *outfile = NULL;

    

    outfile = filp_open(output_file,O_CREAT|O_WRONLY,0755);
if(IS_ERR(outfile)){
		printk("here--\n");
        

return -(PTR_ERR(outfile));

}

    

    

    if(!outfile || IS_ERR(outfile)){

        
		printk("here--\n");
        return -EPERM;

        

    }

    

    if(!outfile->f_op->read){

        
		printk("here--\n");
        return -ENOENT;

    }

    

    struct file *filp = NULL;

    filp = filp_open(filename,O_RDWR,0755);

    oldfs = get_fs();

set_fs(KERNEL_DS);

    

if(IS_ERR(filp)){

        

return -(PTR_ERR(filp));

}

    

    

    if(!filp || IS_ERR(filp)){

        

        return -EPERM;

        

    }

    

    if(!filp->f_op->read){

        

        return -ENOENT;

    }

    

    struct crypto_comp *tfm = crypto_alloc_comp(algoName, 0, CRYPTO_ALG_TYPE_COMPRESS);

    

    

    if(IS_ERR(tfm)) {

        printk("compress: cannot allocate %d\n",PTR_ERR(tfm));

        return PTR_ERR(tfm);

    }

    int compressedValue = 0;

    char * buf;

    while(1){

int bytes_to_write;

        buf = kmalloc(512,GFP_KERNEL);

bytes_to_write=vfs_read(filp,buf,500,&filp->f_pos);

        buf[bytes_to_write+1]='\0';

 	 if(bytes_to_write < 0){

return bytes_to_write;

}

        

        if(bytes_to_write>0){

            /*COMPRESSION*/

            unsigned int dlen = COMP_BUF_SIZE;

            char result[COMP_BUF_SIZE];

            memset(result, 0, sizeof (result));

            

            

            unsigned char src[COMP_BUF_SIZE];

            memset(src, 0, sizeof (src));

            int j=0;

            for(j=0;j<COMP_BUF_SIZE;j++){

                src[j] = buf[j];

                //                printk("\n%x",src[j]);

            }

            

            int ret = crypto_comp_compress(tfm, src, bytes_to_write, result,&dlen);

            if (ret) {

                printk("\nCompression failed %d\n",ret);

                return 0;

            }

            

            printk("\nCompression successful %d\n",dlen);

            

            /* END OF COMPRESSION*/

            

            compressedValue = compressedValue+dlen;

int write_bytes = vfs_write(outfile,result,dlen,&outfile->f_pos);

if(write_bytes < 0){

return write_bytes;

}

}

else{

            kfree(buf);

break;

}

        kfree(buf);

    }

    

    crypto_free_comp(tfm);

    

    set_fs(oldfs);

    if(filp!=NULL && !IS_ERR(filp)){

        filp_close(filp,NULL);

    }

    

    if(outfile!=NULL && !IS_ERR(outfile)){

        filp_close(outfile,NULL);

    }

    

    return compressedValue;

    

}

int decompress_file(char *filename,int algo,char* output_file){

    mm_segment_t oldfs;

	char* algoName = NULL;
	if(algo == 0)
	{
		algoName = kstrdup("deflate", GFP_KERNEL);
	}
	else if(algo == 1)
	{
		algoName = kstrdup("lzo", GFP_KERNEL);
	}
	else
	{
		return -EINVAL;
	}
    struct file *outfile = NULL;

    outfile = filp_open(output_file,O_CREAT|O_WRONLY,0755);

    

    struct file *filp = NULL;

    filp = filp_open(filename,O_RDWR,0755);

    oldfs = get_fs();

set_fs(KERNEL_DS);

    

if(IS_ERR(filp)){

return -(PTR_ERR(filp));

}

    

    if(!filp || IS_ERR(filp)){

        return -EPERM;

    }

    

    if(!filp->f_op->read){

        return -ENOENT;

    }

    

    struct crypto_comp *tfm = crypto_alloc_comp(algoName, 0, CRYPTO_ALG_TYPE_COMPRESS);

    

    

    if(IS_ERR(tfm)) {

        printk("compress: cannot allocate %d\n",PTR_ERR(tfm));

        return PTR_ERR(tfm);

    }

    

    char * buf;

    while(1){

        int bytes_to_write;

        

        buf = kmalloc(512,GFP_KERNEL);

        

        

        

        char *e;

        

bytes_to_write=vfs_read(filp,buf,500,&filp->f_pos);

        e = strchr(buf, '\0');

        int index = (int)(e - buf);

        printk("\nbytes_to_write %d %d\n",bytes_to_write,index);

        buf[bytes_to_write+1]='\0';

 	 if(bytes_to_write < 0){

return bytes_to_write;

}

        if(bytes_to_write>0){

            /*DECOMPRESSION*/

            

            int dlen = COMP_BUF_SIZE;

            char result[COMP_BUF_SIZE];

            memset(result, 0, sizeof (result));

            

            

            unsigned char src[bytes_to_write];

            memset(src, 0, sizeof (src));

            int j=0;

            for(j=0;j<bytes_to_write;j++){

                printk("\nbuf[%d] %x\n",j,buf[j]);

                src[j] = buf[j];

                //                printk("\n%x",src[j]);

            }

            

            

            

            

            int ret = crypto_comp_decompress(tfm, src,bytes_to_write, result,&dlen);

            if (ret) {

                printk("\nDecompression failed %d %d\n",ret,dlen);

                return 0;

            }

            printk("\nDecompression successful %d\n",dlen);

            

            /* END OF DECOMPRESSION*/

            

int write_bytes = vfs_write(outfile,result,dlen,&outfile->f_pos);

if(write_bytes < 0){

return write_bytes;

}

}

else{

            kfree(buf);

break;

}

        kfree(buf);

    }

    

    crypto_free_comp(tfm);

    

    set_fs(oldfs);

    if(filp!=NULL && !IS_ERR(filp)){
		printk("closing file filp\n");
        filp_close(filp,NULL);

    }

    

    if(outfile!=NULL && !IS_ERR(outfile)){
		printk("closing file outfile\n");
        filp_close(outfile,NULL);

    }

    

    return 0;
}

static int do_one_async_hash_op(struct ahash_request *req,

                                struct tcrypt_result *tr,

                                int ret)

{

if (ret == -EINPROGRESS || ret == -EBUSY) {

ret = wait_for_completion_interruptible(&tr->completion);

if (!ret)

ret = tr->err;

INIT_COMPLETION(tr->completion);

}

return ret;

}

static int test_hash(struct crypto_ahash *tfm, struct scatterlist* sg,int psize,char* cs)

{

const char *algo = crypto_tfm_alg_driver_name(crypto_ahash_tfm(tfm));

unsigned int i, j, k, temp;


char result[64];

struct ahash_request *req;

struct tcrypt_result tresult;

   

int ret = -ENOMEM;

    

    

init_completion(&tresult.completion);

    

req = ahash_request_alloc(tfm, GFP_KERNEL);

if (!req) {

printk(KERN_ERR "alg: hash: Failed to allocate request for "

      "%s\n", algo);

goto out_nobuf;

}

ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,

                               tcrypt_complete, &tresult);



    

    ahash_request_set_crypt(req, sg, result, psize-1);

    int rc;

    

    

        ret = do_one_async_hash_op(req, &tresult,

                                   crypto_ahash_init(req));

        if (ret) {

            pr_err("alt: hash: init failed on test  "

                   "for %s: ret=%d\n",  algo, -ret);

            goto out;

        }

        ret = do_one_async_hash_op(req, &tresult,

                                   crypto_ahash_update(req));

        if (ret) {

            pr_err("alt: hash: update failed on test "

                   "for %s: ret=%d\n",  algo, -ret);

            goto out;

        }

        ret = do_one_async_hash_op(req, &tresult,

                                   crypto_ahash_final(req));

        if (ret) {

            pr_err("alt: hash: final failed on test "

                   "for %s: ret=%d\n", algo, -ret);

            goto out;

        }

    

    

    hexdump(result, crypto_ahash_digestsize(tfm));
	int idx;
	for(idx = 0;idx<64;idx++)
	{
		cs[idx] = result[idx];
	}
    //cs = kstrdup(result,GFP_KERNEL);

ret = 0;

    

out:

ahash_request_free(req);

out_nobuf:

    

return ret;

}

int checksum(char* filename, int algo, char* cs){

    struct crypto_ahash *tfm;

int err;

    //TODO algo

    

tfm = crypto_alloc_ahash("md5", 0, CRYPTO_ALG_TYPE_SHASH);

if (IS_ERR(tfm)) {

printk(KERN_ERR "alg: hash: Failed to load transform for %s: "

      "%ld\n", "md5", PTR_ERR(tfm));

return PTR_ERR(tfm);

}

    

    mm_segment_t oldfs;

    

    

    struct file *filp = NULL;

    filp = filp_open(filename,O_RDONLY,0);

    oldfs = get_fs();

set_fs(KERNEL_DS);

    

if(IS_ERR(filp)){

return -(PTR_ERR(filp));

}

    

    if(!filp || IS_ERR(filp)){

        return -EPERM;

    }

    

    if(!filp->f_op->read){

        return -ENOENT;

    }

    int size = 0;

    char * buf;

    while(1){

        int bytes_to_write;

        buf = (char*)kmalloc(4096,GFP_KERNEL);

bytes_to_write=vfs_read(filp,buf,4096,&filp->f_pos);

if(IS_ERR(bytes_to_write) || bytes_to_write < 0){

            int rc = bytes_to_write;

            kfree(buf);

//            goto out;

}

        size = size+bytes_to_write;

        kfree(buf);

        if(!bytes_to_write > 0){

            break;

        }

       

    }

    

    if(filp!=NULL && !IS_ERR(filp)){

        filp_close(filp,NULL);

    }

    

    

    filp = filp_open(filename,O_RDONLY,0);

    

    int arr_size = (size/4096)+1;

    int rem_size = (size%4096)-1;

    size--;

    struct scatterlist sg[arr_size];

    sg_init_table(sg, ARRAY_SIZE(sg));

    int i =0;

    int b = 0; 

    int bufsize;

    int bytes_read=0;

    unsigned char *src;

    unsigned int s ;

    while(1){

        int bytes_to_write;

        if(!b){

            bufsize = rem_size;

            b = 1;

            s = bufsize - 1;

        }

        else{

            if(bytes_read == size){

                break;

            }

            if(bytes_read < size){

                printk("\nbuf alloced\n");

                bufsize = 4096;

                s = bufsize;

            }

            else{

                break;

            }

        }

        char buf[bufsize];

        memset(buf,0,sizeof(buf));

//        buf = (char*)kmalloc(bufsize,GFP_KERNEL);

bytes_to_write=vfs_read(filp,buf,bufsize,&filp->f_pos);

//        printk("\nbuf is %s ",buf);

//        printk("\nbytes_to_write is %d",bytes_to_write);

        printk("\ns is %d\n",s);

        src = kmalloc(s,GFP_KERNEL);

        int g=0;

        for(g=0;g<s;g++){

            src[g] = buf[g];

//            printk("\n%c %x\n",buf[g],src[g]);

        }

        bytes_read = bytes_read+bytes_to_write;

if(IS_ERR(bytes_to_write) || bytes_to_write < 0){

            int rc = bytes_to_write;

//            kfree(buf);

            goto out;

}

        

        if(bytes_to_write>0){

            printk("\n---------------------------");

            printk("\nbufsize %d bytes_to_write %d\n",bufsize,bytes_to_write);

            printk("\nbuf while copy %s\n%s\n",buf,src);

            sg_set_buf(&sg[i],src,strlen(src));

            i++;

        }



        else{

//            kfree(buf);

            break;

        }

//        kfree(buf);

        

    }



    printk("\nbytes_read %d\n",bytes_read);

    

err = test_hash(tfm,sg,size,cs);

    printk("-----check check check %s\n",cs);

    printk("\nsize is %d\n",size);

    

out:

    set_fs(oldfs);

    kfree(src);

    if(filp!=NULL && !IS_ERR(filp)){

        filp_close(filp,NULL);

    }



crypto_free_ahash(tfm);

return err;

}


