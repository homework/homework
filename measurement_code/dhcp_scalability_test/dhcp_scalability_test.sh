#!/bin/bash

for flows in `seq 55 5 200`; do
for try in `seq 1 5`; do
sed -e "s/%flows%/$flows/g" \
      -e "s/%tries%/$try/g" config-proto.cfg | \
      tee config-now.cfg
      ./dhcp_scalability_test config-now.cfg
	sleep 30
      done
done 
