#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "commons.h"

#define __NR_xjob  349

#define DEFLATE 0

#define MAX_PAYLOAD 1024

// 0 - silence mode
// 1 - notify mode

struct my_job arg;
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

void local_sig_handler(int signum)
{
	recvmsg(sock_fd, &msg, 0);
	struct notify_user *nu = (struct notify_user *)NLMSG_DATA(nlh);
	printf("job id is %d\n",nu->jobID);
	printf("ret val is %d\n",nu->ret);
	printf("job type is %d\n",nu->job_type);
	printf("received signal\n");
}

int main(int arc, char *argv[])
{
	int ret = 0,i;
    
    /*------------------initialising section---------------*/
    
	sock_fd=socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    printf("\nsockfd is %d %d\n",sock_fd,errno);
    if(sock_fd<0)
        return -1;
    
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;
    
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    
    nlh->nlmsg_flags = 0;
    //strcpy(NLMSG_DATA(nlh), "Hello");
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
	
	/*------------------end of initialisation--------------*/
	signal(SIGIO, local_sig_handler);

    
    while(1){

	printf("\nEnter the job details");
    printf("\nJob ID:");
    int jobId;
    scanf("%d",&jobId);
    
    
    int output_mode;
    char input_file[256];
    char output_file[256];
    
    printf("\nOperation: 0:Checksum, 1:Encrypt, 2:Decrypt, 3:Compress, 4:Decompress, 5:List of jobs, 6:Remove from queue");
    int input_operation,operation,sub_operation;
    scanf("%d",&input_operation);
    
    
    int algo;
    unsigned char* key;
    if(input_operation == 0){
        operation = 0;
    out_mode1:
        printf("\nOutput Mode: 0:Silent, 1:Notify");
        scanf("%d",&output_mode);
        if(output_mode != 0 && output_mode != 1){
            printf("\nEnter a valid output mode");
            goto out_mode1;
        }
        
        printf("\nInput File:");
        scanf("%s",&input_file);
    check:
        printf("\nEnter the algorithm: 0:MD5");
        scanf("%d",&algo);
        if(algo != 0){
            printf("\nUnsupported algorithm\n");
            goto check;
        }
    }
    if(input_operation == 1){
        operation = 1;
        sub_operation = 0;
    out_mode2:
        printf("\nOutput Mode: 0:Silent, 1:Notify");
        scanf("%d",&output_mode);
        if(output_mode != 0 && output_mode != 1){
            printf("\nEnter a valid output mode");
            goto out_mode2;
        }
        
        printf("\nInput File:");
        scanf("%s",&input_file);
        
        printf("\nOutput File:");
        scanf("%s",&output_file);

    encrypt_algo:
        printf("\nEnter the algorithm: 0:CTR-AES");
        scanf("%d",&algo);
        if(algo != 0){
            printf("\nUnsupported algorithm\n");
            goto encrypt_algo;
        }
        char k[16];
    key1:
        printf("\nEnter the key: ");
        scanf("%s",&k);
        key = (unsigned char*)k;
        if(strlen(key) != 16){
            printf("\nInput Error: Length of key is not equal to 16");
            goto key1;
        }
    }
    if(input_operation == 2){
        operation = 1;
        sub_operation = 1;
    out_mode3:
        printf("\nOutput Mode: 0:Silent, 1:Notify");
        scanf("%d",&output_mode);
        if(output_mode != 0 && output_mode != 1){
            printf("\nEnter a valid output mode");
            goto out_mode3;
        }
        
        printf("\nInput File:");
        scanf("%s",&input_file);
        
        printf("\nOutput File:");
        scanf("%s",&output_file);
    decrypt_algo:
        printf("\nEnter the algorithm: 0:CTR-AES");
        scanf("%d",&algo);
        if(algo != 0){
            printf("\nUnsupported algorithm\n");
            goto decrypt_algo;
        }
        char k[16];
    key2:
        printf("\nEnter the key: ");
        scanf("%s",&k);
        key = (unsigned char*)k;
        if(strlen(key) != 16){
            printf("\nInput Error: Length of key is not equal to 16");
            goto key2;
        }
    }
    if(input_operation == 3){
        operation = 2;
        sub_operation = 0;
    out_mode4:
        printf("\nOutput Mode: 0:Silent, 1:Notify");
        scanf("%d",&output_mode);
        if(output_mode != 0 && output_mode != 1){
            printf("\nEnter a valid output mode");
            goto out_mode4;
        }
        
        printf("\nInput File:");
        scanf("%s",&input_file);
        
        printf("\nOutput File:");
        scanf("%s",&output_file);
    comp_algo:
        printf("\nEnter the algorithm: 0:Deflate, 1:LZO");
        scanf("%d",&algo);
        if(algo != 0 && algo != 1){
            printf("\nUnsupported algorithm\n");
            goto comp_algo;
        }
    }
    if(input_operation == 4){
        operation = 2;
        sub_operation = 1;
    out_mode5:
        printf("\nOutput Mode: 0:Silent, 1:Notify");
        scanf("%d",&output_mode);
        if(output_mode != 0 && output_mode != 1){
            printf("\nEnter a valid output mode");
            goto out_mode5;
        }
        
        printf("\nInput File:");
        scanf("%s",&input_file);
        
        printf("\nOutput File:");
        scanf("%s",&output_file);
        printf("\nEnter the algorithm: 0:Deflate, 1:LZO");
    decomp_algo:
        scanf("%d",&algo);
        if(algo != 0 && algo != 1){
            printf("\nUnsupported algorithm\n");
            goto decomp_algo;
        }
    }
    if(input_operation == 5){
        operation = 5;
    }
    if(input_operation == 6){
        operation = 6;
        printf("\nEnter the Job ID:");
        scanf("%d",&algo);
    }
    
    printf("\n Entered values jobid %d \n operation %d \n sub_operation %d \n algo %d \n infile %s \n outfile %s \n output mode %d\n",jobId,operation,sub_operation,algo,input_file,output_file,output_mode);
    
//    return 0;
    
    
    
    
    
    
    
	    
    
    arg.jobID = jobId;
    arg.ret = 0;
    arg.job_type = operation;
    arg.sockfd = NETLINK_USER;
    arg.pid = getpid();
    arg.output_mode = output_mode;
    arg.filename = strdup(input_file);
    arg.outfile = strdup(output_file);
    
    if(operation == 0){
        arg.chsumargs.algo = algo;
    }
    
    if(operation == 1 ){
        arg.edargs.op = sub_operation;
        arg.edargs.algo = algo;
        int l = 0;
        for (l=0; l<16; l++) {
                arg.edargs.key[l] = key[l];
        }
        arg.edargs.len = strlen(arg.edargs.key);
    }
    
    if(operation == 2){
        arg.compargs.op = sub_operation;
        arg.compargs.algo = algo;
    }
    
    if(operation == 3){
        ret = syscall(__NR_xjob, (void*)&arg);
        printf("returned value from syscall: %d\n",ret);
        for(i=0;i<ret;i++)
        {
            struct currjob_list *jl;
            jl = arg.ljobargs.jl;
            printf("from kernel: %d\n",jl[i].jobID);
            printf("from kernel: %d\n",jl[i].job_type);
            printf("from kernel: %s\n",jl[i].filename);
        }
    }
    
    if(operation == 4){
        arg.rjobargs.jid = algo;
        ret = syscall(__NR_xjob, (void *)&arg);
        printf("returned from remove: %d\n",ret);
    }
    
    
    
    /*
     arg.filename = strdup("encrypt.txt");
     arg.job_type = 1;
     arg.sockfd = NETLINK_USER;
     arg.pid = getpid();
     arg.ret = 0;
     arg.output_mode = NOTIFY;
     arg.outfile = strdup("encrypt_out.txt");
     arg.edargs.op = 0;
     arg.edargs.algo = 0;
     arg.edargs.key = (unsigned char*)strdup("0123456789123456");
     arg.edargs.len = strlen(arg.edargs.key);
     syscall(__NR_xjob, (void*)&arg);
     
     
     arg.filename = strdup("encrypt_out.txt");
     arg.jobID = 1005;
     arg.job_type = 1;
     arg.sockfd = NETLINK_USER;
     arg.pid = getpid();
     arg.ret = 0;
     arg.output_mode = NOTIFY;
     arg.outfile = strdup("encrypt_finish.txt");
     arg.edargs.op = 1;
     arg.edargs.algo = 0;
     arg.edargs.key = (unsigned char*)strdup("0123456789123456");
     arg.edargs.len = strlen(arg.edargs.key);
     syscall(__NR_xjob, (void*)&arg);
     */
    /*
     arg.filename = strdup("encrypt.txt");
     arg.jobID = 1020;
     arg.job_type = 2;
     arg.sockfd = NETLINK_USER;
     arg.pid = getpid();
     arg.ret = 0;
     arg.output_mode = NOTIFY;
     arg.outfile = strdup("compress.txt");
     arg.compargs.op = 0;
     arg.compargs.algo = 0;
     syscall(__NR_xjob, (void*)&arg);
     
     arg.filename = strdup("compress.txt");
     arg.jobID = 1023;
     arg.job_type = 2;
     arg.sockfd = NETLINK_USER;
     arg.pid = getpid();
     arg.ret = 0;
     arg.output_mode = NOTIFY;
     arg.outfile = strdup("decompress.txt");
     arg.compargs.op = 1;
     arg.compargs.algo = 0;
     syscall(__NR_xjob, (void*)&arg);
     */
    
	/*arg.jobID = 1010;
	arg.pid = getpid();
	arg.job_type = 3;
	ret = syscall(__NR_xjob, (void*)&arg);
	printf("returned value from syscall: %d\n",ret);
	for(i=0;i<ret;i++)
	{
		struct currjob_list *jl;
		jl = arg.ljobargs.jl;
		printf("from kernel: %d\n",jl[i].jobID);
		printf("from kernel: %d\n",jl[i].job_type);
		printf("from kernel: %s\n",jl[i].filename);
	}*/
	
    
	/*
     arg.jobID = 1004;
     arg.pid = getpid();
     arg.job_type = 4;
     arg.rjobargs.jid = 1002;
     ret = syscall(__NR_xjob, (void *)&arg);
     printf("returned from remove: %d\n",ret);
     */
	/*
     struct my_job *temp;
     temp = (struct my_job *)malloc(sizeof(struct my_job));
     //temp->ljobargs.buffer = (struct currjob_list *)malloc(sizeof(struct currjob_list)*30);
     temp->jobID = 1003;
     temp->pid = getpid();
     temp->job_type = 3;
     ret = syscall(__NR_xjob, (void*)temp);
     printf("returned value from syscall: %d\n",ret);
     for(i=0;i<ret;i++)
     {
     printf("from kernel v1 %d\n",temp->ljobargs.jl[i].jobID);
     struct currjob_list *jl;
     jl = temp->ljobargs.jl;
     printf("from kernel: %d\n",jl[i].jobID);
     }
     //printf("received from kernel:\n");
     
     //recvmsg(sock_fd, &msg, 0);	
     //printf("%s\n",NLMSG_DATA(nlh));
     printf("out of the loop\n");
     */		
	printf("out of the loop\n");	
	}
	exit(0);
}
