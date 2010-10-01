#!/bin/sh
set -e

NOX_ROOT=/home/mort/homework/nox.git
NOX_PORT=2525

cd ${NOX_ROOT}/build/src

./nox_core -i ptcp:${NOX_PORT} ${@}
