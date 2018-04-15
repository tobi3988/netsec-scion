#!/bin/bash
DURATION=30m
WARMUPTIME=10m
CHANGERATE=1s

##########################################################

echo "start experiment constant packet reordering------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 50ms reorder 25% 50%
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/reordering
cp logs/metrics.csv experiments/logs/reordering/
cp logs/multipath.csv experiments/logs/reordering/

##########################################################

tc qdisc del dev lo root netem
