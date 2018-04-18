#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>  
#include <unistd.h>  
#include <netdb.h>
#include <errno.h>
#include <stdio.h>

#define LISTEN_BACK_LOG 511
#define MAX_EVENTS 64

int epollfd = -1;
int sockfd = -1;

int set_fd_non_block(int fd)
{
	int flags = -1;
	flags = fcntl(fd, F_GETFL, 0);
	if(flags == -1)
	{
		fprintf(stderr, "get fd:%d flags failed, errno=%d\n", fd, errno);
		return -1;
	}
	flags|= O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) == -1)
	{
		fprintf(stderr, "set fd:%d flags failed, errno=%d\n", fd, errno);
		return -2;
	}
	return 0;
}


int create_sock_listen(int port)
{
	struct sockaddr_in addr = {0};
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd == -1)
	{
		fprintf(stderr, "create socket failed, errno=%d\n", errno);
		return -1;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr=INADDR_ANY;
	if(bind(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) == -1)
	{
		fprintf(stderr, "bind socket failed, errno=%d\n", errno);
		close(fd);
		return -2;
	}
	if(set_fd_non_block(fd) != 0) 
	{ 
		fprintf(stderr, "%s", "set fd non block failed\n"); 
		return -3;
	}
	if(listen(fd, LISTEN_BACK_LOG) == -1)
	{
		fprintf(stderr, "listen socket failed, errno=%d\n", errno);
		close(fd);
		return -4;
	}
	return fd;
}

int create_epoll(int sock_fd)
{
	int fd = epoll_create(512);
	if(fd == -1)
	{
		fprintf(stderr, "create epoll failed, errno=%d\n", errno);
		return -1;
	}
	return fd;
}

int main(int argc, char** argv)
{
	struct epoll_event* events;
	struct epoll_event event;
	int ret = -1;
	char* recv_buf[512] = {0};
	char* send_buf[512] = {"hello"};
	sockfd = create_sock_listen(11011);
	fprintf(stderr, "create sock ret=%d\n", sockfd);
	epollfd = create_epoll(sockfd);
	fprintf(stderr, "create epoll ret=%d\n", epollfd);
	event.events = EPOLLIN | EPOLLET;
	//event.events = EPOLLIN;
	event.data.fd = sockfd;
	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &event) == -1)
	{
		fprintf(stderr, "epoll_ctl add failed, errrno=%d\n", errno);
		return -1;
	}
	events = calloc(MAX_EVENTS,sizeof event);
	while(1)
	{
		int retval = epoll_wait(epollfd, events, MAX_EVENTS, 10);
		for(int i = 0; i < retval; i++)
		{
			if((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP))
			{
				fprintf(stderr,"epoll error, fd=%d, errno=%d, events=%d\n", events[i].data.fd, errno, events[i].events);
				close(events[i].data.fd);
				events[i].data.fd = -1;
			}
			if(events[i].events & EPOLLIN)
			{
				//new connection
				if(events[i].data.fd == sockfd)
				{
					fprintf(stderr,"epoll got a new connection\n");
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd;
					char hbuf[NI_MAXHOST],sbuf[NI_MAXSERV];
					in_len = sizeof in_addr;
					infd = accept(sockfd, &in_addr, &in_len);
					if(infd==-1)
					{
						if((errno== EAGAIN) || (errno== EWOULDBLOCK))
						{	
							fprintf(stderr, "accept a new connection failed, need do it again\n");
							continue;
						}
						else
						{
							fprintf(stderr, "accept a new connection success\n");
							continue;
						}
					}
					if(getnameinfo(&in_addr, in_len, hbuf,sizeof hbuf, sbuf,sizeof sbuf,NI_NUMERICHOST | NI_NUMERICSERV) == 0)
					{
						fprintf(stderr, "new connection info,ip=%s, port=%s\n", hbuf, sbuf);
					}
					set_fd_non_block(infd);
					event.data.fd= infd;
					event.events= EPOLLIN | EPOLLET;
					if(epoll_ctl(epollfd, EPOLL_CTL_ADD, infd, &event) == -1)
					{
						fprintf(stderr, "add new connect into epoll\n");
					}
				}
				else
				{	
					memset(recv_buf, 0, 512);
					int ret = read(events[i].data.fd, recv_buf, 512);
					if(ret != 0)
					{
						fprintf(stderr,"epoll got data come in, fd=%d, read ret=%d, data=%s\n", events[i].data.fd, ret, recv_buf);
						event.data.fd = events[i].data.fd;
						event.events = EPOLLOUT | EPOLLIN | EPOLLET;
						ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, events[i].data.fd, &event);
						if(ret == -1)
						{
							fprintf(stderr, "epoll add fd=%d out event failed, errno=%d\n", events[i].data.fd, errno);
						}
					}
					else
					{
						fprintf(stderr,"epoll got data come in, but read ret is 0, peer closed, fd=%d, read ret=%d\n", events[i].data.fd, ret);
						event.data.fd = events[i].data.fd;
                                                event.events = EPOLLOUT | EPOLLIN | EPOLLET;
						int ret = epoll_ctl(epollfd, EPOLL_CTL_DEL, events[i].data.fd, &event);
						if(ret == -1)
						{
							fprintf(stderr, "epoll del fd=%d out event failed, errno=%d\n", events[i].data.fd, errno);
						}
						close(event.data.fd);
					}
				}
			}
			if(events[i].events & EPOLLOUT)
			{
				char* ptr = "hello";
				int ret = send(events[i].data.fd, ptr, strlen(ptr), 0);
				fprintf(stderr,"epoll got data send out, fd=%d, ret=%d\n", events[i].data.fd, ret);
				event.data.fd = events[i].data.fd;
                                event.events = EPOLLIN | EPOLLET;
				ret = epoll_ctl(epollfd, EPOLL_CTL_MOD, events[i].data.fd, &event);
				if(ret == -1)
				{
					fprintf(stderr, "epoll del fd=%d out event failed, errno=%d\n", events[i].data.fd, errno);
				}
			}
		}
	}
	return 0;
}
