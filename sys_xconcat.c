#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#define __user
//structure for holding all parameters
struct myargs{
	__user const char *outfile;
	__user const char** infiles;
	unsigned int infile_count;
	int oflags;
	mode_t mode;
	unsigned int flags;
}*myarg;
//global - holds a value to return
long returnvalue;
asmlinkage extern long (*sysptr)(void *arg, int argslen);

asmlinkage long xconcat(void *arg,int argslen)
{
	struct file *filp = NULL;
	struct file *outfile = NULL;
	unsigned int infile_count;
	mm_segment_t oldfs;
	char *temp;
	int copy_ret;
	int bytes=0,total_bytes = 0,m=0,k=0,no_of_files=0;
	if(arg == NULL){
		return -EINVAL;
	}
	myarg = NULL;
	//copy contents from user and create o/p file
	myarg = kmalloc(sizeof(struct myargs),GFP_KERNEL); 
	copy_ret=copy_from_user(myarg,arg,sizeof(*myarg));
	infile_count = myarg->infile_count;
	if(myarg->infile_count > 10){
		returnvalue = -EPERM;
		goto freeall;
	}
	temp = getname(myarg->outfile);
	outfile = filp_open(temp,myarg->oflags|O_WRONLY,myarg->mode);
	if(!outfile || IS_ERR(outfile) || outfile == NULL || outfile < 0){
		putname(temp);
		returnvalue = -(PTR_ERR(outfile));
		goto freeall;
	}
	putname(temp);
	oldfs = get_fs();	
	set_fs(KERNEL_DS);
	outfile->f_pos = 0;
	//check if i/p files are readable
	for(m=0;m<infile_count;m++){
		char *tmp = getname(myarg->infiles[m]);
		struct file *fp = NULL;
		fp = filp_open(tmp,O_RDONLY,0);
		putname(tmp);
		if(fp == NULL){
			returnvalue = -EPERM;
			goto freeall;
		}
		if(!fp || IS_ERR(fp)){
			returnvalue = -EPERM;
			goto freeall;
		}
		if(!fp->f_op->read){
			returnvalue = -ENOENT;
			goto freeall;
		}
		//check for o/p file = i/p file
		if(fp->f_dentry->d_inode == outfile->f_dentry->d_inode){
			returnvalue = -EPERM;
			goto freeall;
		}
		filp_close(fp,NULL);
	}
	//uncomment to check partial write
	//int fail_count = 0;
	//open in files one by one
	for (k=0;k<infile_count;k++){
		char *buf;
		char *tmp = getname(myarg->infiles[k]);
		filp = filp_open(tmp,O_RDONLY,0);
		putname(tmp);
		if(!filp || IS_ERR(filp)){
			returnvalue = -EPERM;
			goto freeall;
		}
		if(!filp->f_op->read){
			returnvalue = -ENOENT;
			goto freeall;
		}
		//read and write to the files
		while(1){
		int bytes_to_write;
		buf = (char*)kmalloc(4096,GFP_KERNEL);
		bytes_to_write=vfs_read(filp,buf,4096,&filp->f_pos);
		if(bytes_to_write < 0){
			returnvalue = bytes_to_write;
			goto freeall;
		}
		bytes = bytes+bytes_to_write;	
		//uncomment to check partial write
		/*if(fail_count == 2){
			kfree(buf);
			goto returntouser;
		}*/
		if(bytes_to_write>0){
			int write_bytes = vfs_write(outfile,buf,bytes_to_write,&outfile->f_pos);
			if(write_bytes < 0){
				returnvalue = write_bytes;
				goto freeall;
			}
			total_bytes = total_bytes+write_bytes;
		}
		else{
			kfree(buf);
			break;
		}
		kfree(buf);
		//fail_count++;
		}//end of while
	no_of_files++;
	}//end of for
	//retrun values to user based on the flags provided
	//uncomment for partial read/write
	//returntouser:
	set_fs(oldfs);
	if(myarg->flags == 0x01){
		returnvalue = no_of_files;
		goto freeall;
	}
	if(myarg->flags == 0x02){
		if (bytes == 0){
			returnvalue = 0;
		}
		else{
		returnvalue = (100*total_bytes)/bytes;
		}
		goto freeall;
	}
	if(myarg->flags == 0x00){
		returnvalue = total_bytes;
		goto freeall;
	}
	//close all files and free all buffers
	freeall:
		if(outfile!=NULL && !IS_ERR(outfile)){
			filp_close(outfile,NULL);
		}
		if(filp!=NULL && !IS_ERR(filp)){
			filp_close(filp,NULL);
		}
		if(myarg){
			kfree(myarg);
		}
		return returnvalue;
}

static int __init init_sys_xconcat(void)
{
	printk("installed new sys_xconcat module\n");
	if (sysptr == NULL)
		sysptr = xconcat;
	return 0;
}
static void  __exit exit_sys_xconcat(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xconcat module\n");
}
module_init(init_sys_xconcat);
module_exit(exit_sys_xconcat);

MODULE_LICENSE("GPL");
