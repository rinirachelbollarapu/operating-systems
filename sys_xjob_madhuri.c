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
#include "internal.h"
asmlinkage extern long (*sysptr)(void *arg);
struct en_de_crypt_args
{
	int algo;
	int op;	
	long key;
};

struct de_compress_args
{
	int algo;
	int op;
	//char* test;
};

struct checksum_args
{
	int algo;
};

struct list_args
{
	int total;
	void* buffer;
};

struct rem_args
{
	int toberem;
};

struct my_job
{
	int jobID;
	int ret;
	char *filename;
	char *outfile;
    int sockfd;
	union
	{
		struct en_de_crypt_args edargs;
		struct de_compress_args compargs;
		struct checksum_args chsumargs;
		struct list_args ljobargs;
		struct rem_args rjobargs;
	};
}*args;

struct currjob_list
{
	int jobID;
	char filename[256];	
};

struct task_struct *task;
static struct queue *wq;
DEFINE_MUTEX(mutex);
int qlen=0;
int qmax;
wait_queue_head_t pwq;
wait_queue_head_t cwq;

/*------------------------queue funcs--------------*/
struct queue
 {
        struct my_job* job;
		struct queue* next;
 }*rear, *front;

struct queue* pop(void)
{
      struct queue *var;
			var = rear;
      //struct queue *tmp;
		if(rear->next == NULL)
		{
			rear = front = NULL;
			qlen--;
		}
		else if(rear!=NULL)
		{
			rear = rear->next;
			qlen--;
		}
		else
		{
			printk("q empty\n");
		}

	  return var;
}

void push(struct my_job* job)
{
    struct queue *temp;
    temp=(struct queue*)kmalloc(sizeof(struct queue*),GFP_KERNEL);
    temp->job = (struct my_job *)kmalloc(sizeof(struct my_job*),GFP_KERNEL);
	temp->job = job;
	/*
		 temp->job->jobID = job->jobID;
		 temp->job->filename = kstrdup(job->filename,GFP_KERNEL);
		 temp->job->algo = job->algo;
		 temp->job->ret = job->ret;
	*/
	if (front == NULL)
     {
           front=temp;
           front->next=NULL;
           rear=front;
     }
     else
     {
           front->next=temp;
           front=temp;
           front->next=NULL;
     }
	qlen++;
}

/*
void display(void)
{
     struct queue *var=rear;
     if(var!=NULL)
     {
           printk("\nElements are as:  ");
           while(var!=NULL)
           {
                printk("\t%d",var->Data);
                var=var->next;
           }
     printk("\n");
     } 
     else
     printk("\nQueue is Empty");
}
*/

struct queue* initialize_queue(int size)
{
	front = rear = NULL;
	qmax = size;
	return front;
}

void destroy_queue(struct queue* wq)
{
	struct queue* tmp;
	while(wq)
	{
		tmp = wq->next;
		kfree(wq);
		wq = tmp;
	}
}

int list_jobs(void* buffer)
{
	struct queue* tmp = rear;
	int count = 0;
	struct currjob_list jl[30];
	while(tmp != NULL)
	{
		jl[count].jobID = tmp->job->jobID;
		//jl[count].filename = kstrdup(tmp->job->filename,GFP_KERNEL);
		strcpy(jl[count].filename,tmp->job->filename); 
		count++;
		//copy into array of structures
		tmp = tmp->next;
	}
	//char* newstr = kstrdup("sending from kernel",GFP_KERNEL);
	//copy_to_user(&buffer,newstr,strlen(newstr));
	//&buffer = kstrdup("sending from kernel",GFP_KERNEL);	
	//memcpy(buffer,newstr,strlen(newstr));	
	memcpy(buffer,&jl,sizeof(jl));
	return count;
}

/*------------------------end of queue funcs-------*/

int compress_file(char *filename,int algo,char* output_file){
    
    printk("\nin compress_file\n");
    printk("\ncompress_file: %s %s\n",filename,output_file);
    struct file *filp = NULL;
    filp = filp_open("/usr/src/hw3-cse506g22/hw3/some1.txt",O_CREAT|O_RDONLY,0);
    
	if(IS_ERR(filp)){
        printk("\ntest a %d\n",-(PTR_ERR(filp)));
		return -(PTR_ERR(filp));
	}
    mm_segment_t oldfs;
    struct file *outfile = NULL;
    char* algoName;

	if(algo == 0)
	{
		algoName = kstrdup("deflate",GFP_KERNEL);
	}
    outfile = filp_open(output_file,O_CREAT|O_WRONLY,0);
    
    
    oldfs = get_fs();
	set_fs(KERNEL_DS);
    
    
    printk("\ntest b\n");

    if(!filp || IS_ERR(filp)){
        printk("\ntest c\n");

        return -EPERM;
        
    }
    printk("\ntest d\n");

    if(!filp->f_op->read){
        printk("\ntest e\n");

        return -ENOENT;
    }
    printk("\ntest f\n");

    struct crypto_comp *tfm = crypto_alloc_comp(algoName, 0, CRYPTO_ALG_ASYNC);
    printk("\ntest g\n");

    
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
        printk("\ntest h %d\n",bytes_to_write);

        if(bytes_to_write>0){
            /*COMPRESSION*/
            int dst_len1 = 512;
            char dst1[512];
            memset(dst1,0,sizeof(dst1));
            
            char src1[512];
            memset(src1,0,sizeof(src1));
            strcpy(src1,buf);
            int src_len1 = strlen(src1);
            printk("\ntest i\n");

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
    
	kfree(algoName);
    return 0;
}

int decompress_file(char *filename,int algo,char* output_file){
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
    char *algoName;
    if(algo == 0)
	{
		algoName = kstrdup("deflate",GFP_KERNEL);
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
    kfree(algoName);
    return 0;
    
}



int process_job(struct my_job* job)
{
	printk("inside process_job\n");
	printk("-----------job id: %d\n",job->jobID);
	//printk("-----------file name: %s\n",job->filename);
	if(job->jobID == 2)
	{
        printk("\ntest 1\n");
        printk("\nfilename is %s\n",job->filename);
       
        
        
		struct de_compress_args compargs = job->compargs;
        printk("\compargs.algo is %d\n",compargs.algo);
        
        if(compargs.algo == 0){
		compress_file(job->filename,compargs.algo,job->outfile);
        }
        if(compargs.algo == 1){
        decompress_file(job->filename,compargs.algo,job->outfile);
        }
	}
    
    
	return 0;
}

int consume(void)
{
	struct queue *q;
	int ret;

	printk("inside consume %d\n",qmax);
	mutex_lock(&mutex); 
	if(qlen == 0)
	{
		mutex_unlock(&mutex);
		wait_event_interruptible(cwq,qlen>0);
		return 0;
	}
	q = pop();
	if(qlen < qmax)
	{
		wake_up_interruptible(&pwq);
	}
	mutex_unlock(&mutex);  
	ret = process_job(q->job);
	kfree(q);
	schedule();
	return ret;
}

int consumer_init(void)
{
	int i=0,j;
		
	for(;;)
	{
		j = consume();
		printk("finished one job %d\n",i);
		i++;
	}
	
	return 0;
}
asmlinkage long xjob(void *arg)
{
	int err = 0,tmpvar;
	
	printk("inside syscall\n");
	args = (struct my_job *)kmalloc(sizeof(struct my_job), GFP_KERNEL);
	tmpvar = copy_from_user(args, arg, (unsigned long)sizeof(struct my_job));
	printk("got from user %d\n",args->jobID);
	//printk("got from user %s\n",args->filename);
	
	struct list_args ljobargs = args->ljobargs;
	if(args->jobID == 3)
	{
		err = list_jobs(ljobargs.buffer);
		//printk("before returning %s\n", ljobargs.buffer);
		
		if(copy_to_user((void*)arg,(void *)args,(unsigned long)sizeof(struct my_job)))
		{
			printk("copying failed\n");
			return -EFAULT;
		}
		
		goto out;
	}

	/*	
	struct de_compress_args compargs = args->compargs;
	printk("got from user %d\n",compargs.op);
	printk("got from user %d\n",compargs.algo);	
	printk("got from user %s\n",compargs.test);
	*/
	mutex_lock(&mutex); 	
	if(qlen >= qmax)
	{
		mutex_unlock(&mutex);
		wait_event_interruptible(pwq,qlen<qmax);
		goto out_lock;
	}
	push(args);  	
	wake_up_interruptible(&cwq);

out_lock:
	mutex_unlock(&mutex);
out:  
	return err;
}

static int __init init_sys_xjob(void)
{
	int err=0;
	
	if(sysptr == NULL)
		sysptr = xjob;

	wq = initialize_queue(20); 
	task = kthread_create(consumer_init,NULL,"consumerthread");
	if(task)
	{
		printk("this was missing\n");
		wake_up_process(task);
	}
	
	init_waitqueue_head(&pwq);
	init_waitqueue_head(&cwq);
	printk("installed new sys_xjob module\n");
	return err;
}
static void  __exit exit_sys_xjob(void)
{
	//kthread_stop(task); 
	destroy_queue(wq); 
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xjob module\n");
}
module_init(init_sys_xjob);
module_exit(exit_sys_xjob);

MODULE_LICENSE("GPL");
