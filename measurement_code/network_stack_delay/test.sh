echo rem_device_all > /proc/net/pktgen/kpktgend_0
echo add_device eth2 > /proc/net/pktgen/kpktgend_0
echo clone_skb 0 > /proc/net/pktgen/eth2
echo delay 244140 > /proc/net/pktgen/eth2
echo count 17061 > /proc/net/pktgen/eth2
echo pkt_size 512 > /proc/net/pktgen/eth2
echo dst_min 10.3.0.1 > /proc/net/pktgen/eth2
echo dst_max 10.3.0.11 > /proc/net/pktgen/eth2
echo flag IPDST_RND > /proc/net/pktgen/eth2
echo vlan_id 0xffff > /proc/net/pktgen/eth2
echo vlan_p 0 > /proc/net/pktgen/eth2
echo vlan_cfi 0 > /proc/net/pktgen/eth2
echo dst_mac 10:20:30:40:50:60 > /proc/net/pktgen/eth2
echo src_mac 10:20:30:40:50:61 > /proc/net/pktgen/eth2
echo src_min 10.2.0.1 > /proc/net/pktgen/eth2
echo src_max 10.2.0.1 > /proc/net/pktgen/eth2
echo tos 4 > /proc/net/pktgen/eth2
echo udp_src_max 8080 > /proc/net/pktgen/eth2
echo udp_src_min 8080 > /proc/net/pktgen/eth2
echo udp_dst_max 8080 > /proc/net/pktgen/eth2
echo udp_dst_min 8080 > /proc/net/pktgen/eth2
echo start > /proc/net/pktgen/pgctrl

