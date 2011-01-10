#!/bin/bash

eval `ssh-agent`
ssh-add /home/psacr/.ssh/id_rsa

for flows in 1 `seq 5 5 200`; do
for try in `seq 1 5`; do
#ssh root@10.3.0.2 "cd /home/homenet/homework/nox.git/build/src/; ./nox_core -i ptcp:localhost homework" &
#pid=$!
#echo nox_core--$pid
sleep 10
sed -e "s/%flows%/$flows/g" \
      -e "s/%tries%/$try/g" config-proto.cfg | \
      tee config-now.cfg
      ./dhcp_scalability_test config-now.cfg
#      kill $pid
      done
done 
