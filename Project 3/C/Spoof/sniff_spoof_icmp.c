#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include "myheader.h"

void send_raw_ip_packet(struct ipheader *ip);

void send_icmp_reply(struct ipheader *ip)
{
  char buffer[512];

  memset((char *)buffer, 0, 512);
  memcpy((char *)buffer, ip, ntohs(ip->iph_len));
  struct ipheader *spoofed_ip = (struct ipheader *)buffer;
  struct icmpheader *spoofed_icmp = (struct icmpheader *)(buffer + ip->iph_ihl * 4);

  // Exchange source and destination addresses
  spoofed_ip->iph_sourceip = ip->iph_destip;
  spoofed_ip->iph_destip = ip->iph_sourceip;

  // Since this is an ICMP reply the type must be 0
  spoofed_icmp->icmp_type = 0;

  send_raw_ip_packet(spoofed_ip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800)
  { // 0x0800 is IP type
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));

    /* determine protocol */
    switch (ip->iph_protocol)
    {
    case IPPROTO_TCP:
      printf("   Protocol: TCP\n");
      return;
    case IPPROTO_UDP:
      printf("   Protocol: UDP\n");
      return;
    case IPPROTO_ICMP:
      printf("   Protocol: ICMP\n");
      send_icmp_reply(ip);
      return;
    default:
      printf("   Protocol: others\n");
      return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype] = 8";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); // Close the handle
  return 0;
}
