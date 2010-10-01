#!/bin/sh
set -e

PIDFILE=/tmp/ofprotocol.pid
LOGFILE=/tmp/ofprotocol.log
ROOT=/home/mort
LEVEL=dbg # info|emer|err|warn|dbg

cd ${ROOT}

[ -r "${PIDFILE}" ] && sudo kill $(cat ${PIDFILE})
sudo ofprotocol -Fclosed -D --log-file=${LOGFILE} -vANY:syslog:${LEVEL} -P${PIDFILE} tcp:localhost:2525 unix:/var/run/dp0.sock
