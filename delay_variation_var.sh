#!/bin/bash

echo "start experiment variational one way packet delay variation"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 100ms 1ms
su -c 'cd ${SC} && ./scion.sh stop' - parallels

rm -f logs/metrics.csv
rm -f logs/multipath.csv
rm -f network.log
su -c 'cd ${SC} && ./scion.sh start' - parallels

sleep $2

for i in {1..25..1}
do
    tc qdisc change dev lo root netem delay 100ms ${i}ms
    echo $(($(date +%s%N)/1000000)),$i*3 >> network.log
    sleep $1
done

for i in {24..1..1}
do
    tc qdisc change dev lo root netem delay 100ms ${i}ms
    echo $(($(date +%s%N)/1000000)),$i >> network.log
    sleep $1
done

su -c 'cd ${SC} && ./scion.sh stop' - parallels

mkdir -p experiments/logs/variation_var
cp logs/metrics.csv experiments/logs/variation_var/
cp logs/multipath.csv experiments/logs/variation_var/
cp network.log experiments/logs/variation_var/
