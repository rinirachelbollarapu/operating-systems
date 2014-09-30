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

#define NETLINK_USER 31
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
    while (len--)
        printk("%02x", *buf++);
    
    printk("\n");
}



int aes_decrypt(const void *k, int key_len,  char *cipher_text, char **clear_text, size_t size) {
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    
    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
    int rc;
    
    if(IS_ERR(tfm)) {
        printk("aes_decrypt: cannot allocate cipher\n");
        rc = PTR_ERR(tfm);
        goto out;
    }
    u8 key[] = {0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07,
        0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12};
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
        pr_err("aes_encrypt: encryption failed %d\n", rc);
        goto out;
    }
    
    rc=0;
    
    
out:
    return rc;
}


int aes_encrypt(const void *k, int key_len, const char *clear_text, char **cipher_text, size_t size) {
    
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    
    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
    int rc;
    
    if(IS_ERR(tfm)) {
        printk("aes_encrypt: cannot allocate cipher\n");
        rc = PTR_ERR(tfm);
        goto out;
    }
    printk("\ntest 1 \n");
    u8 key[] = {0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07,
        0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12};
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
        *cipher_text = (char*)kmalloc(size,GFP_KERNEL);
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
    return rc;
}

int get_md5_hash(char *dest, char *src, size_t size) {
    printk("\nin get_md5_hash\n");
    struct scatterlist sg;
    struct hash_desc desc;
    int rc = 0;
    
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

int compress_file(char *filename,char* algoName,char* output_file){
    
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
    
    struct crypto_comp *tfm = crypto_alloc_comp(algoName, 0, CRYPTO_ALG_ASYNC);
    
    
    if(IS_ERR(tfm)) {
        printk("compress: cannot allocate cipher %d\n",PTR_ERR(tfm));
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
            
            char src1[512];
            memset(src1,0,sizeof(src1));
            strcpy(src1,buf);
            int src_len1 = strlen(src1);
            
            int ret = crypto_comp_compress(tfm, src1, src_len1, dst1,&dst_len1);
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

int decompress_file(char *filename,char* algoName,char* output_file){
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
    
    struct crypto_comp *tfm = crypto_alloc_comp(algoName, 0, CRYPTO_ALG_ASYNC);
    
    
    if(IS_ERR(tfm)) {
        printk("compress: cannot allocate cipher %d\n",PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }
    
    //    char *buf;
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
            /*DECOMPRESSION*/
            int dst_len1 = 512;
            char dst1[512];
            memset(dst1,0,sizeof(dst1));
            
            char src1[512];
            memset(src1,0,sizeof(src1));
            strcpy(src1,buf);
            int src_len1 = strlen(src1);
            
            int ret = crypto_comp_decompress(tfm, src1, src_len1, dst1,&dst_len1);
            if (ret) {
                printk("\nDecompression failed %d\n",ret);
                return 0;
            }
            printk("\nDecompression successful\n");
            
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

int encrypt_file(char *filename,int algo,char *output_file, char* key1,int key_len){
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
        buf = (char*)kmalloc(512,GFP_KERNEL);
		bytes_to_write=vfs_read(filp,buf,512,&filp->f_pos);
		if(IS_ERR(bytes_to_write) || bytes_to_write < 0){
			 rc = bytes_to_write;
            kfree(buf);
            goto out;
		}
        
        if(bytes_to_write>0){
            struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
            
            struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
            
            
            if(IS_ERR(tfm)) {
                printk("aes_encrypt: cannot allocate cipher\n");
                rc = PTR_ERR(tfm);
                return rc;
                //        goto out;
            }
            
            unsigned char key[key_len];
            int i=0;
            for(i=0;i<key_len;i++){
                key[i] = key1[i];
            }
            
            rc = crypto_blkcipher_setkey(tfm, key, sizeof(key));
            if(rc) {
                printk("aes_encrypt: cannot set key %d\n",rc);
                goto out;
            }

            
            
            struct scatterlist src[1], dst[1];
            sg_init_table(src, 1);
            /*ENCRYPTION*/
            char* clear_text;
            clear_text = kmalloc(sizeof(char*),GFP_KERNEL);
            
            strcpy(clear_text, buf);
            int len = strlen(clear_text);
            char *cipher_text ;
            cipher_text = kmalloc(sizeof(char*),GFP_KERNEL);
            if (!cipher_text) {
                printk("taes ERROR: alloc free page error\n");
                goto out;
            }
            memset(cipher_text, 0, 512);
            sg_set_buf(src, clear_text, PAGE_SIZE);
            sg_set_buf(dst, cipher_text, PAGE_SIZE);
            
            rc = crypto_blkcipher_encrypt(&desc, dst, src, len);

            if(rc<0) {
                pr_err("aes_encrypt: encryption failed %d\n", rc);
                goto out;
            }
            
            printk("\nEncryption successful\n");
            /* END OF ENCRYPTION*/
            
			int write_bytes = vfs_write(outfile,cipher_text,bytes_to_write,&outfile->f_pos);
            
			if(IS_ERR(write_bytes) ){
               
                goto out;
//				rc = write_bytes;
//                goto freebuf;
			}
            
            
                        rc=0;

            kfree(clear_text);
//            kfree(cipher_text);
            crypto_free_blkcipher(tfm);
            
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
        buf = (char*)kmalloc(512,GFP_KERNEL);
		bytes_to_write=vfs_read(filp,buf,512,&filp->f_pos);
		if(IS_ERR(bytes_to_write) || bytes_to_write < 0){
            rc = bytes_to_write;
            kfree(buf);
            goto out;
		}
        
        if(bytes_to_write>0){
            struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
            
            struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
            
            
            if(IS_ERR(tfm)) {
                printk("aes_encrypt: cannot allocate cipher\n");
                rc = PTR_ERR(tfm);
                return rc;
                //        goto out;
            }
            
            unsigned char key[key_len];
            int i=0;
            for(i=0;i<key_len;i++){
                key[i] = key1[i];
            }
            
            rc = crypto_blkcipher_setkey(tfm, key, sizeof(key));
            if(rc) {
                printk("aes_encrypt: cannot set key %d\n",rc);
                goto out;
            }
            
            
            
            struct scatterlist src[1], dst[1];
            sg_init_table(src, 1);
            /*ENCRYPTION*/
            char* clear_text;
            clear_text = kmalloc(sizeof(char*),GFP_KERNEL);
            
            
            char *cipher_text ;
            cipher_text = kmalloc(sizeof(char*),GFP_KERNEL);
            strcpy(cipher_text, buf);
            int len = strlen(cipher_text);
            if (!cipher_text) {
                printk("taes ERROR: alloc free page error\n");
                goto out;
            }
            memset(clear_text, 0, 512);
            sg_set_buf(src, cipher_text, PAGE_SIZE);
            sg_set_buf(dst, clear_text, PAGE_SIZE);
            
            rc = crypto_blkcipher_decrypt(&desc, dst, src, len);
            
            if(rc<0) {
                pr_err("decrypt: decryption failed %d\n", rc);
                goto out;
            }
            
            printk("\nDecryption successful\n");
            /* END OF ENCRYPTION*/
            
			int write_bytes = vfs_write(outfile,clear_text,bytes_to_write,&outfile->f_pos);
            
			if(IS_ERR(write_bytes) ){
                
                goto out;
                //				rc = write_bytes;
                //                goto freebuf;
			}
            
            
            rc=0;
            
//            kfree(clear_text);
            kfree(cipher_text);
            crypto_free_blkcipher(tfm);
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


asmlinkage long xjob(void *arg)
{
    
    j = NULL;
    //copy contents from user and create o/p file
    j = kmalloc(sizeof(struct job),GFP_KERNEL);
    copy_from_user(j,arg,sizeof(*j));
    
    
    /* Encryption */
    /* char* clear_text = kmalloc(32,GFP_KERNEL);
     clear_text = "this is the text to be tested for encryption";
     int len = strlen(clear_text);
     char *cipher_text ;
     aes_encrypt("12345", 5,clear_text , &cipher_text,  len);
     printk("\noriginal text %s \n encrypted text %s\n",clear_text,cipher_text);
     */
    
    char *algoName1;
    
    algoName1 = kstrdup("deflate",GFP_KERNEL);
    
    char *filename1;
    
    filename1 = kstrdup("11",GFP_KERNEL);
    
    char * output_file1;
   
    output_file1 = kstrdup("22",GFP_KERNEL);
    
    encrypt_file(filename1,0,output_file1,j->name,j->pid);
    
    kfree(filename1);
    kfree(algoName1);
    kfree(output_file1);
    
    
    /* Decryption */
    /*
     char *clear_text2;
     aes_decrypt("12345", 5,cipher_text ,&clear_text2 ,  len);
     printk("\nencrypted text %s \n decrypted text %s\n",cipher_text,clear_text2);
     */
    
   char *algoName2;
    
    algoName2 = kstrdup("deflate",GFP_KERNEL);
    
    char *filename2;
    
    filename2 = kstrdup("22",GFP_KERNEL);
    
    char * output_file2;
    
    output_file2 = kstrdup("33",GFP_KERNEL);

    
    decrypt_file(filename2,0,output_file2,j->name,j->pid);
    
    kfree(filename2);
    kfree(algoName2);
    kfree(output_file2);

    
    /*Compression*/
    
    
    /*char *algoName1;
     algoName1 = kmalloc(sizeof(char*),GFP_KERNEL);
     algoName1 = kstrdup("deflate",GFP_KERNEL);
     
     char *filename1;
     filename1 = kmalloc(sizeof(char*),GFP_KERNEL);
     filename1 = kstrdup("1",GFP_KERNEL);
     
     char * output_file1;
     output_file1 = kmalloc(sizeof(char*),GFP_KERNEL);
     output_file1 = kstrdup("2",GFP_KERNEL);
     
     compress_file(filename1,algoName1,output_file1);
     
     kfree(filename1);
     kfree(algoName1);
     kfree(output_file1);*/
    
    /* Decompression */
    /*char *algoName2;
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
     kfree(output_file2);*/
    
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
