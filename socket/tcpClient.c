#include <stdio.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <string.h>
#include <errno.h> 
  
int main(){  
  int clientSocket;  
  char buffer[1024]={0};  
  struct sockaddr_in serverAddr;  
  socklen_t addr_size;  
  
  /*---- Create the socket. The three arguments are: ----*/  
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */  
  clientSocket = socket(PF_INET, SOCK_STREAM, 0);  
    
  /*---- Configure settings of the server address struct ----*/  
  /* Address family = Internet */  
  serverAddr.sin_family = AF_INET;  
  /* Set port number, using htons function to use proper byte order */  
  serverAddr.sin_port = htons(5701);  
  /* Set IP address to localhost */  
  serverAddr.sin_addr.s_addr = inet_addr("172.24.20.17");  
  /* Set all bits of the padding field to 0 */  
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);    
  
  /*---- Connect the socket to the server using the address struct ----*/  
  addr_size = sizeof serverAddr;  
  int ret =connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size); 
	printf("connect sucesss\n"); 
 printf("1-----------------------\n"); 

	char data[4]={'H','Z','C','\0'};
	
 printf("2-----------------------\n"); 
	ret = send(clientSocket, data, 3, 0);
 printf("3-----------------------\n"); 
	printf("send data ret=%d, errno=%d\n", ret, errno);
	
  /*---- Read the message from the server into the buffer ----*/  
  ret = recv(clientSocket, buffer, 1024, 0); 
 
  /*---- Print the received message ----*/  
  printf("Data recv ret=%d\n",ret);     
	for(int i=0;i<3;i++)
		printf("%d %c\n", i,buffer[i]);
	printf("\n");
	
 
	char data2[71]={0};
	ret = send(clientSocket, data2, 70, 0);
	
 
  
  ret = recv(clientSocket, buffer, 1024, 0);
	printf("recv again,ret=%d\n",ret); 
  
  
  return 0;  
}
