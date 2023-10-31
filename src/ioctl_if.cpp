#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"

uint32_t ioctl_get_ipv4_addr(int socket_fd, int if_cmd, const char *interface_name,
                                    ifreq *ifr, const char *log_label) {
  if (ifr == NULL || socket_fd < 0) {
    return -1;
  }
  strncpy(ifr->ifr_name, interface_name, IFNAMSIZ);
  struct sockaddr_in *sin;
  if (ioctl(socket_fd, if_cmd, ifr) != 0) {
    return -1;
  } else {
    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr->ifr_addr;
    char ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip_address, sizeof(ip_address));
    LOGI("%s addr: %s\n", log_label, ip_address);
    return addr->sin_addr.s_addr;
  }
}

void ioctl_ifconf_inet4() {
  LOGV("ioctl_ifconf_inet4");
  struct ifconf ifc;
  struct ifreq ifr_arr[4]; // You can increase this number as needed

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    LOGE("ioctl_ifconf_inet4 socket error");
    return;
  }
  ifc.ifc_len = sizeof(ifr_arr);
  ifc.ifc_req = ifr_arr;
  if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) { // cmd ifconfig
    LOGE("failed to SIOCGIFCONF");
    close(fd);
    return;
  }

  int interfaces_count = ifc.ifc_len / sizeof(struct ifreq);
  LOGD("ifc.ifc_len %x, ifconf struct size %lx, ifreq struct size %lx", ifc.ifc_len,
       sizeof(struct ifconf), sizeof(struct ifreq));
  for (int i = 0; i < interfaces_count; i++) {
    ifreq ifr = ifr_arr[i];
    LOGI("SIOCGIFCONF get interface %d: %s, flags %d", i, ifr.ifr_name, ifr.ifr_flags);
    struct sockaddr_in *ip_addr = (struct sockaddr_in *) &(ifr.ifr_addr);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_addr->sin_addr), ip_str, INET_ADDRSTRLEN);
    LOGI("Interface %s, IP %s", ifr.ifr_name, ip_str);
    ioctl_get_ipv4_addr(fd, SIOCGIFADDR, ifr.ifr_name, &ifr, "SIOCGIFADDR");
    ioctl_get_ipv4_addr(fd, SIOCGIFBRDADDR, ifr.ifr_name, &ifr, "SIOCGIFBRDADDR");
    ioctl_get_ipv4_addr(fd, SIOCGIFNETMASK, ifr.ifr_name, &ifr, "SIOCGIFNETMASK");
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
      if (ifr.ifr_flags & IFF_UP) {
        LOGD("UP (Interface %s is running)", ifr.ifr_name);
      } else {
        LOGD("DOWN (Interface %s is not running)", ifr.ifr_name);
      }
    }
  }
  close(fd);
}