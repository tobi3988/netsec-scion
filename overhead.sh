#!/bin/bash

echo "start experiment overhead"
tc qdisc del dev lo root netem
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
rm -f logs/overhead_handle.csv
rm -f logs/overhead_propagate.csv
rm -f network.log
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep 30m

su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/overhead
cp logs/overhead_handle.csv experiments/logs/overhead/
cp logs/overhead_propagate.csv experiments/logs/overhead/
