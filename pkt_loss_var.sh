#!/bin/bash

echo "start experiment variational packet loss"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 50ms
su -c 'cd ${SC} && ./scion.sh stop' - parallels

rm -f logs/metrics.csv
rm -f network.log
su -c 'cd ${SC} && ./scion.sh start' - parallels

sleep $2

for i in {0.5..2.0..0.05}
do
    tc qdisc change dev lo root netem loss ${i}%
    echo $(($(date +%s%N)/1000000)),$(($i*3)) >> network.log
    sleep $1
done

for i in {2.0..0.5..0.05}
do
    tc qdisc change dev lo root netem loss ${i}%
    echo $(($(date +%s%N)/1000000)),$(($i*3)) >> network.log
    sleep $1
done

su -c 'cd ${SC} && ./scion.sh stop' - parallels

mkdir -p experiments/logs/packet_loss_var
cp logs/metrics.csv experiments/logs/packet_loss_var/
cp network.log experiments/logs/packet_loss_var/
