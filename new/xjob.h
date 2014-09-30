#ifndef __xjob_h
#define __xjob_h

#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/wait.h>

#include "commons.h"

struct queue
{
    struct my_job* job;
	struct queue* next;
};

extern void testing(void);
extern struct queue* pop(void);
extern struct queue* priority_pop(void);
extern void push(struct my_job* job);
extern struct queue* initialize_queue(int size);
extern void destroy_queue(struct queue* wq);
extern int list_jobs(struct currjob_list*);
extern int remove_job(int jid);
extern int qlen;
extern int qmax;

extern int aes_encrypt( char *key1, int key_len, char *clear_text, char **cipher_text, size_t size);
extern int encrypt_file(char *filename,int algo,char *output_file, char* key1,int key_len);
extern int decrypt_file(char *filename,int algo,char *output_file, char* key1,int key_len);
extern int aes_decrypt(char *key1, int key_len, char *cipher_text, char **clear_text, size_t size);
extern int decompress_file(char *filename,int algo,char* output_file);
extern int compress_file(char *filename,int algo,char* output_file);
extern int checksum(char* filename, int algo, char* cs);

#endif

