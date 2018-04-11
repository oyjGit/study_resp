#include <stdio.h>  
#include <stdlib.h>  
  
#include <string.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <netdb.h>  
  
int port=6789;  
int main(int argc, char** argv) {  
    int socket_descriptor; //套接口描述字  
    int iter=0;  
    int so_broadcast = 1;
    char buf[80] = {0}; 
    char data = 'a'; 
    char sendBuf = (char*)malloc(1024*1024);
    struct sockaddr_in address;//处理网络通信的地址  
  
    bzero(&address,sizeof(address));  
    address.sin_family=AF_INET;  
    address.sin_addr.s_addr=inet_addr(argv[1]);//这里不一样  
    address.sin_port=htons(port);  
  
    //创建一个 UDP socket  
  
    socket_descriptor=socket(AF_INET,SOCK_DGRAM,0);//IPV4  SOCK_DGRAM 数据报套接字（UDP协议） 
    setsockopt(socket_descriptor,SOL_SOCKET,SO_BROADCAST,&so_broadcast,sizeof(so_broadcast));// 设置广播属性 
  
    for(iter=0;iter<=1000;iter++)  
    {  
         /* 
         * sprintf(s, "%8d%8d", 123, 4567); //产生：" 123 4567"  
         * 将格式化后到 字符串存放到s当中 
         */  
        //sprintf(buf,"data packet with ID %d\n",iter);  
        //sprintf(buf,"%d\n",iter);  
        buf[0]=data++;
         
        /*int PASCAL FAR sendto( SOCKET s, const char FAR* buf, int len, int flags,const struct sockaddr FAR* to, int tolen);　　 
         * s：一个标识套接口的描述字。　 
         * buf：包含待发送数据的缓冲区。　　 
         * len：buf缓冲区中数据的长度。　 
         * flags：调用方式标志位。　　 
         * to：（可选）指针，指向目的套接口的地址。　 
         * tolen：to所指地址的长度。   
　　      */  
        sendto(socket_descriptor,buf,strlen(buf),0,(struct sockaddr *)&address,sizeof(address));
	printf("type a key to continue\n");
	getchar();  
    }  
  
    sprintf(buf,"stop\n");  
    sendto(socket_descriptor,buf,sizeof(buf),0,(struct sockaddr *)&address,sizeof(address));//发送stop 命令  
    close(socket_descriptor);  
    printf("Messages Sent,terminating\n");  
  
    exit(0);  
  
    return (EXIT_SUCCESS);  
}  
