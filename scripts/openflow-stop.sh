#!/bin/sh
set -e

for p in $(ps aux | grep of[dp] | tr -s ' ' | cut -f 2 -d " ") ; do 
  sudo kill $p 
done
