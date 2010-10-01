#!/bin/sh
set -e

OVS_ROOT=/home/mort/homework/openvswitch.git
NOX_PORT=2525
ETH0_ADDR=$(ifconfig eth0 | grep inet | tr -s " " | cut -f 3 -d " " | cut -f 2 -d ":")

insmod ${OVS_ROOT}/datapath/linux-2.6/openvswitch_mod.ko && echo "+++ MODULE LOADED" || echo "!!! MODULE ALREADY LOADED"

ovs-dpctl add-dp dp0 || echo "!!! DATAPATH ALREADY CREATED"
ovs-dpctl add-if dp0 eth0 || echo "!!! INTERFACE ALREADY ADDED"

ifconfig eth0 0.0.0.0
ifconfig dp0 ${ETH0_ADDR}
route add default gw ${ETH0_ADDR%.*}.1

ovs-openflowd --fail=closed dp0 tcp:${ETH0_ADDR}:${NOX_PORT}
