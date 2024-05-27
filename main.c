
#include <pcap/pcap.h>
#include <stdio.h>
#include <sys/types.h>


void packet_handler(u_char *user, const struct pcap_pkthdr *header,const u_char *packet) {
    printf("Packet: length %d\n", header->len);
}

int main() {


char errbuf[PCAP_ERRBUF_SIZE]; 
pcap_t *p;

p = pcap_open_offline("cap.pcap", errbuf);

pcap_loop(p, 0,packet_handler, NULL);

//pcap_freealldevs(pcap_if_t *);
pcap_close(p);

}