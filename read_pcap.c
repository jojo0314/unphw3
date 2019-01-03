#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

struct sockaddr_in src,dst;

int main(int argc,char *argv[]){

    char error[PCAP_ERRBUF_SIZE];
    char *cmd ="";
    pcap_t *handle = pcap_open_offline(argv[1],error);
    struct pcap_pkthdr *header;
    u_char *data;

    if(argc == 3){
        cmd = argv[2];
    }
    if(!handle){
        printf("%s",error);
        return 0;
    }
    printf("Open:%s\n",argv[1]);
 
    struct bpf_program fliter;
    if(pcap_compile(handle,&fliter,cmd,1,PCAP_NETMASK_UNKNOWN)==-1){
        printf("pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 0;
    }
    if(strlen(cmd)!=0)  printf("Fliter:%s\n",cmd);
    printf("\n");
    
    int cnt = 1;
    while(pcap_next_ex(handle,&header,&data)>=0){

        if(pcap_offline_filter(&fliter,header,data)==0) continue;
        struct tm *ltime;
        char timestr[40];
        time_t local_tv_sec;

        local_tv_sec =header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr,sizeof(timestr),"%b %d, %Y:%H:%M:%S",ltime);

        printf("Packet #%d\n",cnt++);
        printf("Time: %s.%.6d\n",timestr,(int)header->ts.tv_usec);
        printf("Packet len: %d\n",header->len);

       // const u_char *buffer;
        struct iphdr *iph = (struct iphdr*)(data+sizeof(struct ethhdr));
        unsigned short iphdrlen = iph -> ihl*4;

        memset(&src,0,sizeof(src));
        memset(&dst,0,sizeof(dst));

        src.sin_addr.s_addr = iph -> saddr;
        dst.sin_addr.s_addr= iph -> daddr;

        printf("source ip :%s\n",inet_ntoa(src.sin_addr));
        printf("destination ip :%s\n",inet_ntoa(dst.sin_addr));

        struct tcphdr *tcph = (struct tcphdr*)(data+iphdrlen+sizeof(struct ethhdr));

        printf("source port :%u\n",ntohs(tcph->source));
        printf("destination port :%u\n",ntohs(tcph->dest));


        printf("\n");

    }
    pcap_close(handle);
}
