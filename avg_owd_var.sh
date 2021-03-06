#!/bin/bash

echo "start experiment variational one way packet delay"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 50ms
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
rm -f network.log
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep $2

for i in {50..100..1}
do
    tc qdisc change dev lo root netem delay ${i}ms
    echo $(($(date +%s%N)/1000000)),$(($i*3)) >> network.log
    sleep $1
done

for i in {100..50..1}
do
    tc qdisc change dev lo root netem delay ${i}ms
    echo $(($(date +%s%N)/1000000)),$(($i*3)) >> network.log
    sleep $1
done

su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/avg_owd_var
cp logs/metrics.csv experiments/logs/avg_owd_var/
cp logs/multipath.csv experiments/logs/avg_owd_var/
cp network.log experiments/logs/avg_owd_var/
