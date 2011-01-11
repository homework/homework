#!/bin/bash

type='exact';

#for flows in `seq 325000 50000 1000000`; do
 #   for try in `seq 1 5`; do
#	modprobe -r pktgen
#	sleep 10
#	modprobe pktgen
#	sed -e "s/%type%/$type/g" -e "s/%flows%/$flows/g" \
#	    -e "s/%tries%/$try/g" config-proto.cfg | \
#	    tee config-now.cfg
#	./switch_code_test config-now.cfg
#	curl -k -X GET https://10.2.0.1/ws.v1/switch_delay_test/resetflows
#	
 #   done
#done 

type='wildcard';
for flows in 1 `seq 250 250 10000` `seq 25000 50000 1000000`; do
    for try in `seq 1 5`; do
        modprobe -r pktgen
        sleep 10
        modprobe pktgen
        sed -e "s/%type%/$type/g" -e "s/%flows%/$flows/g" \
            -e "s/%tries%/$try/g" config-proto.cfg | \
            tee config-now.cfg
        ./switch_code_test config-now.cfg
        curl -k -X GET https://10.2.0.1/ws.v1/switch_delay_test/resetflows
	
    done
done
