#!/bin/bash

for pkt_size in 70 500; do
    for flows in `seq 5 5 100`; do
	for try in 1 2 3 4 5; do
	    sed -e "s/%flows%/$flows/g"  -e "s/%pkt_size%/$pkt_size/g" \
		-e "s/%tries%/$try/g" config-proto.cfg | \
		tee config-now.cfg
	    time ./network_stack_test config-now.cfg
	    curl --noproxy 10.3.0.1 -k -X GET https://10.3.0.1/ws.v1/network_stack_test/resetflows
	done
    done 
done
