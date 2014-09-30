//
//  user_application.c
//  
//
//  Created by Rini Rachel on 5/1/14.
//
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#define __NR_xjob 349
struct job{
    unsigned char* name;
    unsigned int pid;
}j;
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define NETLINK_USER 31

#define MAX_PAYLOAD 1024  /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;
int main(int argc, char **argv){
    printf("\ncalling sys_xjob\n");
    int opt_char;
    while ((opt_char = getopt(argc, argv, "k:rh")) != -1){
        switch(opt_char) {
			case 'k':
                j.name = malloc(sizeof(char*));
                j.name = (unsigned char*)optarg;
                j.pid = strlen(j.name);
				break;
            default:
                    break;
		}
    }

    syscall(__NR_xjob,(void*)&j);
    printf("\nsys_xjob was successful\n");
    return 0;
     
     
    /*int childpid = fork();
    if(childpid == 0){
        printf("\nin main of user\n");
        sock_fd=socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
        printf("\nsockfd is %d %d\n",sock_fd,errno);
        if(sock_fd<0)
            return -1;
        printf("\n1\n");
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();         
        printf("\n2\n");
        bind(sock_fd, (struct sockaddr*)&src_addr,
             sizeof(src_addr));
        
        memset(&dest_addr, 0, sizeof(dest_addr));
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;   
        dest_addr.nl_groups = 0; 
        printf("\n3\n");
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlh->nlmsg_pid = getpid();
        printf("pid %d",getpid());
        nlh->nlmsg_flags = 0;
        strcpy(NLMSG_DATA(nlh), "Hello");
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        
        printf("Sending message to kernel\n");
        //    sendmsg(sock_fd,&msg,0);
        j.name = malloc(sizeof(char*));
        j.name = "test";
        j.pid = getpid();
        syscall(__NR_xjob,(void*)&j);
        printf("Waiting for message from kernel\n");
        
        
        recvmsg(sock_fd, &msg, 0);
        printf(" Received message payload in child: %s\n",
               NLMSG_DATA(nlh));
        close(sock_fd);

    }
    else{
        printf("\nin main of user\n");
        sock_fd=socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
        printf("\nsockfd is %d %d\n",sock_fd,errno);
        if(sock_fd<0)
            return -1;
        printf("\n1\n");
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();  
        printf("\n2\n");
        bind(sock_fd, (struct sockaddr*)&src_addr,
             sizeof(src_addr));
        
        memset(&dest_addr, 0, sizeof(dest_addr));
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;   
        dest_addr.nl_groups = 0; 
        printf("\n3\n");
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
        nlh->nlmsg_pid = getpid();
        printf("pid %d",getpid());
        nlh->nlmsg_flags = 0;
        strcpy(NLMSG_DATA(nlh), "Hello");
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        
        printf("Sending message to kernel\n");
        //    sendmsg(sock_fd,&msg,0);
        j.name = malloc(sizeof(char*));
        j.name = "test";
        j.pid = getpid();
        syscall(__NR_xjob,(void*)&j);
        printf("Waiting for message from kernel\n");
        
        
        recvmsg(sock_fd, &msg, 0);
        printf(" Received message payload in parent: %s\n",
               NLMSG_DATA(nlh));
        close(sock_fd);

    }*/
    
}
