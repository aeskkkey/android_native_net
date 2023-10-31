#include  <linux/rtnetlink.h>
#include "common.h"

int main(int argc, char const* argv[]) {
  ioctl_ifconf_inet4(); // ifconfig
  netlink_ip_cmd(RTM_GETNEIGH); // ip neigh
  netlink_ip_cmd(RTM_GETROUTE); // ip route
  netlink_ip_cmd(RTM_GETLINK); // ip link
}