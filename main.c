#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <sys/types.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* don't fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

#define P_TCP 0x06
#define T_IP 0x0800

void packet_handler(u_char* user,
                    const struct pcap_pkthdr* header,
                    const u_char* packet) {
  static int count = 1;  // counter

  printf("%d  ", count);
  count++;

  printf("PACKET: Length %d \n\n", header->len);

  /*  for (int i = 0; i < header->len; i++) {  // hex
      printf("%02x  ", packet[i]);
      if ((i + 1) % 16 == 0) {
        printf("\n");
      }
    }
  */

  const struct sniff_ethernet* ethernet; /* The ethernet header */
  const struct sniff_ip* ip;             /* The IP header */
  const struct sniff_tcp* tcp;           /* The TCP header */
  const char* payload;                   /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;

  ethernet = (struct sniff_ethernet*)(packet);

  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip) * 4;

  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp) * 4;

  switch (htons(ethernet->ether_type)) {
    case 0x0800:  // IP

      /*  if (size_tcp > 24) {
            printf("invalid IP header length %u bytes\n", size_tcp);
            return;
          }
      */
      switch (ip->ip_p) {
        case 6:  // TCP
          printf("TCP\n\n");
          printf("      sPORT: %d\n", htons(tcp->th_sport));
          printf("      dPORT: %d\n", htons(tcp->th_dport));
          printf("       From: %s\n", inet_ntoa(ip->ip_src));
          printf("         To: %s\n", inet_ntoa(ip->ip_dst));

          break;

        case 17:  // UDP
          printf("UDP\n\n");
          printf("      sPORT: %d\n", htons(tcp->th_sport));
          printf("      dPORT: %d\n", htons(tcp->th_dport));
          printf("       From: %s\n", inet_ntoa(ip->ip_src));
          printf("         To: %s\n", inet_ntoa(ip->ip_dst));

          break;

        case 1:  // ICMP
          printf("ICMP");
          break;

        case 2:  // IGMP
          printf("IGMP");
          break;
      }
      break;

    case 0x0806:
      printf("ARP: NO info(for now)");
      break;

    default:
      printf("NOT IP");
      break;
  }

  // payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

  printf("\n*************************************************\n");
}

int main() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* p;

  pcap_if_t *alldevs, *d;

  struct bpf_program fp; /* The compiled filter expression */
  char filter_exp[] = "port 443";

  bpf_u_int32 mask;
  bpf_u_int32 net;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error finding devices: %s\n", errbuf);
    return 1;
  }

  d = alldevs;  // first dev

  /*
  if (pcap_lookupnet(d->name, &net, &mask, errbuf) == -1) {
     fprintf(stderr, "Couldn't get netmask for device %s: %s\n", d->name,
             errbuf);
     net = 0;
     mask = 0;
   }
 */

  p = pcap_open_live(d->name, SNAP_LEN, 1, 1000, errbuf);
  // p = pcap_open_offline("sniff.pcap", errbuf);
  if (p == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
    pcap_freealldevs(alldevs);
    return 2;
  }

  if (pcap_compile(p, &fp, filter_exp, 0, net) == -1) {
    printf("filter doesn't work :(( %s: %s\n", filter_exp, pcap_geterr(p));
    return (2);
  }

  if (pcap_setfilter(p, &fp) == -1) {
    printf("cant apply filter :(( %s: %s\n", filter_exp, pcap_geterr(p));
    return (2);
  }

  pcap_loop(p, 100, packet_handler, NULL);

  pcap_freecode(&fp);
  pcap_freealldevs(alldevs);
  pcap_close(p);

  return 0;
}