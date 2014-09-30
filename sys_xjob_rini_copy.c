//
//  sys_xjob.c
//
//
//  Created by Rini Rachel on 4/30/14.
//
//


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
#include <linux/mutex.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/rng.h>

#include "internal.h""
#define NETLINK_USER 31
#define XBUFSIZE        8
static struct netlink_kernel_cfg cfg;
struct sock *nl_sk = NULL;
#define PFX "from the sys call: "
#define MAX_BLK_SIZE (64*1024*1024)
#define MIN_BLK_SIZE (16)

#define DATA_SIZE       16
#define ENCRYPT_ALGO "ctr(aes)"

#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)


#define CRYPTO_TFM_MODE_ECB             0x00000001
#define CRYPTO_TFM_MODE_CBC             0x00000002
#define CRYPTO_TFM_MODE_CFB             0x00000004
#define CRYPTO_TFM_MODE_CTR             0x00000008

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

asmlinkage extern long (*sysptr)(void *arg);
struct workqueue_struct *wq;
EXPORT_SYMBOL_GPL(wq);
struct job{
    unsigned char* name;
    unsigned int pid;
}*j;
int i=0;
static int crypto_compress(struct crypto_tfm *tfm,
                           const u8 *src, unsigned int slen,
                           u8 *dst, unsigned int *dlen)
{
    printk("\ncrypto_compress: src:%s, dst:%s\n",src,dst);
    //    return 0;
	return tfm->__crt_alg->cra_compress.coa_compress(tfm, src, slen, dst,
	                                                 dlen);
}

static int crypto_decompress(struct crypto_tfm *tfm,
                             const u8 *src, unsigned int slen,
                             u8 *dst, unsigned int *dlen)
{
	return tfm->__crt_alg->cra_compress.coa_decompress(tfm, src, slen, dst,
	                                                   dlen);
}



static void
hexdump(unsigned char *buf, unsigned int len)
{
    printk("\nshow hexdump\n");
    while (len--)
        printk("%02x", *buf++);
    
    printk("\n");
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


int aes_encrypt(char *key1, int key_len, char *clear_text, char **cipher_text, size_t size) {
    
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    
    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
    int rc;
    
    if(IS_ERR(tfm)) {
        printk("aes_encrypt: cannot allocate cipher\n");
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
        printk("aes_encrypt: cannot set key\n");
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
        if (!clear_text) {
            printk("taes ERROR: alloc free page error\n");
            goto out;
        }
        
        sg_set_buf(src+i, clear_text, PAGE_SIZE);
        
        
        
        *cipher_text = kmalloc(size,GFP_KERNEL);
        
        if (!*cipher_text) {
            printk("taes ERROR: alloc free page error\n");
            goto out;
        }
        sg_set_buf(dst+i, *cipher_text, PAGE_SIZE);
        
    }
    rc = crypto_blkcipher_encrypt(&desc, dst, src, size);
    
    crypto_free_blkcipher(tfm);
    
    if(rc<0) {
        pr_err("aes_encrypt: encryption failed %d\n", rc);
        goto out;
    }
    rc=0;
    
out:
    kfree(src);
    kfree(dst);
    return rc;
}

int get_md5_hash(char *dest, char *src, size_t size) {
    printk("\nin get_md5_hash\n");
    struct scatterlist sg;
    struct hash_desc desc;
    int rc = 0;
    //    struct hash_desc desc;
    desc.flags = 0;
    desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
    if(IS_ERR(desc.tfm)) {
        printk("get_md5_hash: error attempting to allocate crypto context\n");
        rc= PTR_ERR(desc.tfm);
        goto normal_exit;
    }
    printk("\nin get_md5_hash test1\n");
    
    rc= crypto_hash_init(&desc);
    if(rc) {
        printk("get_md5_hash: error initializing crypto hash\n");
        goto normal_exit;
    }
    printk("\nin get_md5_hash test2\n");
    
    sg_init_one(&sg, src, size);
    printk("\nin get_md5_hash test3\n");
    
    rc= crypto_hash_update(&desc, &sg, size);
    if(rc) {
        printk("get_md5_hash: error updating crypto hash\n");
        goto normal_exit;
    }
    printk("\nin get_md5_hash test4\n");
    
    rc= crypto_hash_final(&desc, dest);
    if(rc) {
        printk("get_md5_hash: error finalizing crypto hash\n");
        goto normal_exit;
    }
    printk("\nin get_md5_hash test5\n");
    
normal_exit:
    return rc;
}

int deflate_compression(char *filename,char* algoName,char* output_file){
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
    
    struct crypto_comp *tfm = crypto_alloc_comp(algoName, 0, CRYPTO_ALG_TYPE_COMPRESS);
    
    
    
    if(IS_ERR(tfm)) {
        printk("compress: cannot allocate %d\n",PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }
    
    char buf[512];
    memset(buf,0,sizeof(buf));
    while(1){
		int bytes_to_write;
        //		buf = (u8*)kmalloc(512,GFP_KERNEL);
		bytes_to_write=vfs_read(filp,buf,512,&filp->f_pos);
		if(bytes_to_write < 0){
			return bytes_to_write;
		}
        
        if(bytes_to_write>0){
            /*COMPRESSION*/
            int dst_len1 = 512;
            char dst1[512];
            memset(dst1,0,sizeof(dst1));
            
            
            int ret = crypto_compress(tfm, buf, bytes_to_write, dst1,&dst_len1);
            if (ret) {
                printk("\nCompression failed\n");
                return 0;
            }
            
            printk("\nCompression successful\n");
            
            /* END OF COMPRESSION*/
            
            
			int write_bytes = vfs_write(outfile,dst1,bytes_to_write,&outfile->f_pos);
			if(write_bytes < 0){
				return write_bytes;
			}
		}
		else{
            
			break;
		}
        
    }
    
    crypto_free_comp(tfm);
    
    set_fs(oldfs);
    if(filp!=NULL && !IS_ERR(filp)){
        filp_close(filp,NULL);
    }
    
    if(outfile!=NULL && !IS_ERR(outfile)){
        filp_close(outfile,NULL);
    }
    
    return 0;
    
}

int compress_file(char *filename,char* algoName,char* output_file){
    mm_segment_t oldfs;
    struct file *outfile = NULL;
    
    outfile = filp_open(output_file,O_CREAT|O_WRONLY,0);
    
    struct file *filp = NULL;
    filp = filp_open(filename,O_RDWR,0);
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
		bytes_to_write=vfs_read(filp,buf,512,&filp->f_pos);
//        buf[bytes_to_write+1]='\0';
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
            
//            printk("\nCompression successful %d\n",dlen);
            
            /* END OF COMPRESSION*/
            
            /*******/
       
            /*******/
            
            
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

int decompress_file(char *filename,char* algoName,char* output_file){
    mm_segment_t oldfs;
    struct file *outfile = NULL;
    outfile = filp_open(output_file,O_CREAT|O_WRONLY,0);
    
    struct file *filp = NULL;
    filp = filp_open(filename,O_RDWR,0);
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
        printk("decompress: cannot allocate %d\n",PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }
    
    char * buf;
    while(1){
        int bytes_to_write;
        
        buf = kmalloc(4096,GFP_KERNEL);
        
		bytes_to_write=vfs_read(filp,buf,4096,&filp->f_pos);
        
        printk("\nbytes_to_write %d %c\n",bytes_to_write,buf[0]);
//        buf[bytes_to_write+1]='\0';
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
//                printk("\nbuf[%d] %x\n",j,buf[j]);
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
        filp_close(filp,NULL);
    }
    
    if(outfile!=NULL && !IS_ERR(outfile)){
        filp_close(outfile,NULL);
    }
    
    return 0;
    
}

int encrypt_file(char *filename,int algo,char *output_file, char* key1,int key_len){
    
    printk("\n---------1\n");
    
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
        
        if(bytes_to_write>0){
            
            int len = strlen(buf);
            
            char *cipher_text ;
            aes_encrypt(key1, key_len,buf , &cipher_text,  bytes_to_write);
            
            
            
			int write_bytes = vfs_write(outfile,cipher_text,bytes_to_write,&outfile->f_pos);
            
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


//version 2
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




static void hello_nl_recv_msg(struct sk_buff *skb)
{
	printk("hi..!\n");
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg="Hello from kernel :) :D";
    int res;
    
    printk(KERN_INFO "Entering: hello_nl_recv_msg\n");
    
    msg_size=strlen(msg);
    
    nlh=(struct nlmsghdr*)skb->data;
    printk(KERN_INFO "Netlink received msg payload: %s\n",(char*)nlmsg_data(nlh));
    //    pid = nlh->nlmsg_pid; /*pid of sending process */
    pid = j->pid;
    skb_out = nlmsg_new(msg_size,0);
    
    if(!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
    
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh),msg,msg_size);
    
    res=nlmsg_unicast(nl_sk,skb_out,pid);
    
    if(res<0)
        printk(KERN_INFO "Error while sending bak to user\n");
    
    //    netlink_kernel_release(nl_sk);
}

static int testmgr_alloc_buf(char *buf[XBUFSIZE])
{
	int i;
    
	for (i = 0; i < XBUFSIZE; i++) {
		buf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!buf[i])
			goto err_free_buf;
	}
    
	return 0;
    
err_free_buf:
	while (i-- > 0)
		free_page((unsigned long)buf[i]);
    
	return -ENOMEM;
}

static void testmgr_free_buf(char *buf[XBUFSIZE])
{
	int i;
    
	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)buf[i]);
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
    cs = kstrdup(result,GFP_KERNEL);

    
	ret = 0;
    
out:
	ahash_request_free(req);
out_nobuf:
    
	return ret;
}

int checksum(char* filename, int algo,char* cs){
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


asmlinkage long xjob(void *arg)
{
    
    j = NULL;
    //copy contents from user and create o/p file
    j = kmalloc(sizeof(struct job),GFP_KERNEL);
    copy_from_user(j,arg,sizeof(*j));
    
    /*CHECKSUM*/
    char *cs;
    cs = kmalloc(64,GFP_KERNEL);
    checksum( "checksome",  0,cs);
    printk("\ncs %s\n",cs);
    
    
    
    /* Encryption */
    /* char* clear_text = kmalloc(32,GFP_KERNEL);
     clear_text = "this is the text to be tested for encryption";
     int len = strlen(clear_text);
     char *cipher_text ;
     aes_encrypt("12345", 5,clear_text , &cipher_text,  len);
     printk("\noriginal text %s \n encrypted text %s\n",clear_text,cipher_text);
     */
    
     /*char *algoName1;
     
     algoName1 = kstrdup("deflate",GFP_KERNEL);
     
     char *filename1;
     
     filename1 = kstrdup("11",GFP_KERNEL);
     
     char * output_file1;
     
     output_file1 = kstrdup("22",GFP_KERNEL);
     
     encrypt_file(filename1,0,output_file1,j->name,j->pid);
     
     kfree(filename1);
     kfree(algoName1);
     kfree(output_file1);*/
    
    printk("\nDECRYPTION\n");
    /* Decryption */
    /*
     char *clear_text2;
     aes_decrypt("12345", 5,cipher_text ,&clear_text2 ,  len);
     printk("\nencrypted text %s \n decrypted text %s\n",cipher_text,clear_text2);
     */
    
    /*char *algoName2;
     
     algoName2 = kstrdup("deflate",GFP_KERNEL);
     
     char *filename2;
     
     filename2 = kstrdup("22",GFP_KERNEL);
     
     char * output_file2;
     
     output_file2 = kstrdup("33",GFP_KERNEL);
     
     
     decrypt_file(filename2,0,output_file2,j->name,j->pid);
     
     kfree(filename2);
     kfree(algoName2);
     kfree(output_file2);*/
    
    
    /*Compression*/
    
    
   /* char *algoName1;
     algoName1 = kmalloc(sizeof(char*),GFP_KERNEL);
     algoName1 = kstrdup("deflate",GFP_KERNEL);
     
     char *filename1;
     filename1 = kmalloc(sizeof(char*),GFP_KERNEL);
     filename1 = kstrdup("1",GFP_KERNEL);
     
     char * output_file1;
     output_file1 = kmalloc(sizeof(char*),GFP_KERNEL);
     output_file1 = kstrdup("2",GFP_KERNEL);
     
     int compressedValue = compress_file(filename1,algoName1,output_file1);
    
    printk("\nFile compressed to %d\n",compressedValue);
    
     kfree(filename1);
     kfree(algoName1);
     kfree(output_file1);*/
    
    /* Decompression */
     char *algoName2;
     algoName2 = kmalloc(sizeof(char*),GFP_KERNEL);
     algoName2 = kstrdup("deflate",GFP_KERNEL);
     
     char *filename2;
     filename2 = kmalloc(sizeof(char*),GFP_KERNEL);
     filename2 = kstrdup("2",GFP_KERNEL);
     
     char * output_file2;
     output_file2 = kmalloc(sizeof(char*),GFP_KERNEL);
     output_file2 = kstrdup("3",GFP_KERNEL);
     
     decompress_file(filename2,algoName2,output_file2);
     
     kfree(filename2);
     kfree(algoName2);
     kfree(output_file2);
    
    /*NETLINK*/
    
    /*struct nlmsghdr *nlh;
     int pid;
     struct sk_buff *skb_out;
     int msg_size;
     char *msg;//="Hello from kernel :) :D";
     int res;
     
     printk(KERN_INFO "Entering: hello_nl_recv_msg\n");
     
     msg_size=strlen(msg);
     
     
     
     j = NULL;
     //copy contents from user and create o/p file
     j = kmalloc(sizeof(struct job),GFP_KERNEL);
     copy_from_user(j,arg,sizeof(*j));
     printk("\njob id is %d\n",j->pid);
     if(i ==0){
     pid = j->pid;
     skb_out = nlmsg_new(msg_size,0);
     
     if(!skb_out)
     {
     printk(KERN_ERR "Failed to allocate new skb\n");
     return;
     }
     nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
     
     NETLINK_CB(skb_out).dst_group = 0;
     msg = (char*)kmalloc(sizeof(char*),GFP_KERNEL);
     sprintf(msg, "%d", pid);
     strncpy(nlmsg_data(nlh),msg,msg_size);
     
     res=nlmsg_unicast(nl_sk,skb_out,pid);
     
     if(res<0)
     printk(KERN_INFO "Error while sending bak to user\n");
     //    i++;
     }*/
    return 0;
    
}


static int __init init_sys_xjob(void)
{
    printk("installed new sys_xjob module\n");
    //    wq = alloc_workqueue("xjob",
    //                         WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE, 1);
    
    //
    //    printk("\npid in sys call is %d\n",j->pid);
    
    /*nl_sk=netlink_kernel_create(&init_net, NETLINK_USER,0,hello_nl_recv_msg,NULL,THIS_MODULE );
     if(!nl_sk)
     {
     printk("\nerr is %d\n",nl_sk);
     printk(KERN_ALERT "Error creating socket in hello_init.\n");
     return -10;
     }
     else{
     printk("socket created %d",nl_sk);
     }*/
    
    if (sysptr == NULL)
        sysptr = xjob;
    return 0;
}
static void  __exit exit_sys_xjob(void)
{
    //    destroy_workqueue(wq);
    if (sysptr != NULL)
        sysptr = NULL;
    netlink_kernel_release(nl_sk);
    printk("removed sys_xjob module\n");
}
module_init(init_sys_xjob);
module_exit(exit_sys_xjob);

MODULE_LICENSE("GPL");
