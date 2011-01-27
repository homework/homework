#!/bin/bash

for flows in 1 `seq 5 5 100`; do
    for try in `seq 1 5`; do
	sed -e "s/%flows%/$flows/g" \
	  -e "s/%tries%/$try/g" config-proto.cfg | \
	  tee config-now.cfg
	  ./network_stack_test config-now.cfg
	sleep 30
    done
done 
