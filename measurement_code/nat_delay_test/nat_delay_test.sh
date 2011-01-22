#!/bin/bash

for flows in 1 `seq 105 5 200`; do
    for try in `seq 1 5`; do
	sed -e "s/%flows%/$flows/g" \
	  -e "s/%tries%/$try/g" config-proto.cfg | \
	  tee config-now.cfg
	  ./nat_delay_test config-now.cfg
	sleep 120
    done
done 
