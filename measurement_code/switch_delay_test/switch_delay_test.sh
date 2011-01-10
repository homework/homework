#!/bin/bash

for type in 'exact' 'wildcard'; do
    for flows in `seq 10000 100000 1000000`; do
	for try in `seq 1 5`; do
	     modprobe -r pktgen
	     sleep 10
	     modprobe pktgen
	     sed -e "s/%type%/$type/g" -e "s/%flows%/$flows/g" \
		 -e "s/%tries%/$try/g" config-proto.cfg | \
		 tee config-now.cfg
	     ./switch_code_test config-now.cfg
	done
    done 
done
