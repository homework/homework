#!/bin/sh
set -e

OVS_ROOT=/home/mort/homework/openvswitch.git
NOX_PORT=2525
DP0_ADDR=$(ifconfig dp0 | grep inet | tr -s " " | cut -f 3 -d " " | cut -f 2 -d ":")

killall ovs-openflowd || echo "!!! NOTHING TO KILL"
ovs-dpctl del-dp dp0
ifconfig eth0 ${DP0_ADDR}
route add default gw ${DP0_ADDR%.*}.1
rmmod openvswitch_mod
