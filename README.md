Examples of android native code for af_net. 

- `ifconfig`: ioctl with SIOCGIFCONF
- socket connect to kernel with `AF_NETLINK`
    - `ip neigh`: RTM_GETNEIGH
    - `ip route`: RTM_GETROUTE
    - `ip link`: RTM_GETLINK

References:

- https://github.com/torvalds/linux/blob/master/samples/bpf/xdp_router_ipv4_user.c#L442

- https://gist.github.com/cl4u2/5204374