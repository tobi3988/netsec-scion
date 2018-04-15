#!/bin/bash

echo "start experiment variational packet loss"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem loss 0.5%
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
rm -f network.log
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep $2

for i in 0.5 1.0 1.5 2.0 2.5 3.0 3.5 4.0 4.5 5.0 5.5 6.0 6.5 7.0 7.5 8.0 7.5 7.0 6.5 6.0 5.5 5.0 4.5 4.0 3.5 3.0 2.5 2.0 1.5 1.0 0.5
do
    tc qdisc change dev lo root netem loss ${i}%
    echo $(($(date +%s%N)/1000000)),$i >> network.log
    sleep $1
done

su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/packet_loss_var
cp logs/metrics.csv experiments/logs/packet_loss_var/
cp logs/multipath.csv experiments/logs/packet_loss_var/
cp network.log experiments/logs/packet_loss_var/
