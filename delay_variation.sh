#!/bin/bash
DURATION=30m
WARMUPTIME=10m
CHANGERATE=1s


echo "start experiment constant packet delay variation------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 100ms 20ms
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/variation
cp logs/metrics.csv experiments/logs/variation/
cp logs/multipath.csv experiments/logs/variation/

tc qdisc del dev lo root netem
