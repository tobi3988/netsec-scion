#!/bin/bash

echo "start experiment variational packet loss"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem loss 0.5
su -c 'cd ${SC} && ./scion.sh stop' - parallels

rm -f logs/metrics.csv
rm -f network.log
su -c 'cd ${SC} && ./scion.sh start' - parallels

sleep $2

for i in 0.5 0.6 0.7 0.8 0.9 1.0 1.1 1.2 1.3 1.4 1.5 1.6 1.7 1.8 1.9 2.0 1.9 1.8 1.7 1.6 1.5 1.4 1.3 1.2 1.1 1.0 0.9 0.8 0.7 0.6 0.5
do
    tc qdisc change dev lo root netem loss ${i}%
    echo $(($(date +%s%N)/1000000)),$i >> network.log
    sleep $1
done

su -c 'cd ${SC} && ./scion.sh stop' - parallels

mkdir -p experiments/logs/packet_loss_var
cp logs/metrics.csv experiments/logs/packet_loss_var/
cp network.log experiments/logs/packet_loss_var/
