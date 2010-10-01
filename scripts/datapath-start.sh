#!/bin/sh
set -e

PIDFILE=/tmp/ofdatapath.pid
ROOT=/home/mort
LEVEL=dbg # info|emer|err|warn|dbg

cd ${ROOT}

[ -r "${PIDFILE}" ] && sudo kill $(cat ${PIDFILE})
## sudo ofdatapath -D -vANY:syslog:${LEVEL} -P${PIDFILE} -i eth0,eth1,wlan0 punix:/var/run/dp0.sock
sudo ofdatapath -D -vANY:syslog:${LEVEL} -P${PIDFILE} -i eth0 punix:/var/run/dp0.sock
