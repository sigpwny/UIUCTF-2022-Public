#! /bin/bash
# Copyright 2022 Google LLC.
# SPDX-License-Identifier: Apache-2.0

set -ex

ip netns add bridge
ip netns add flag

ip link add jail_br type veth peer jail_if
ip link add flag_br type veth peer flag_if

ip link set jail_if address 4a:c5:2d:9b:8c:8d
ip link set flag_if address 8a:15:22:31:b4:fc

ip link set jail_br netns bridge
ip link set flag_br netns bridge

ip link set jail_if netns jail
ip link set flag_if netns flag

ip -n bridge link add br0 type bridge
ip -n bridge link set br0 up

ip -n bridge link set jail_br up master br0
ip -n bridge link set flag_br up master br0

ip -n jail link set jail_if up
ip -n jail -6 route add default dev jail_if

ip -n flag link set flag_if up
ip -n flag -6 route add default dev flag_if

ip -n jail link set lo up

ip netns exec bridge nft add table ip6 filter
ip netns exec bridge nft add chain ip6 filter forward { type filter hook forward priority 0 \; policy drop \; }
ip netns exec bridge nft add rule ip6 filter forward ether saddr 4a:c5:2d:9b:8c:8d ether daddr 8a:15:22:31:b4:fc accept
ip netns exec bridge nft add rule ip6 filter forward ether saddr 8a:15:22:31:b4:fc ether daddr 4a:c5:2d:9b:8c:8d ip6 saddr 2001:db8:6e02:2663:8815:22ff:fe31:b4fc accept
ip netns exec bridge nft add rule ip6 filter forward ether saddr 8a:15:22:31:b4:fc ip6 nexthdr ipv6-icmp accept

# You may see the csum being incorrect. For details see
# https://patchwork.ozlabs.org/project/netdev/patch/51F15E50.8080208@guap.ru/
# ip netns exec jail ethtool -K jail_if tx off
# ip netns exec flag ethtool -K flag_if tx off

ip netns exec flag bash -c "(while true; do timeout 0.1 nc -u 2001:db8:6e02:2663:48c5:2dff:fe9b:8c8d 16611 < /mnt/flag &> /dev/null; sleep 1; done) &"
