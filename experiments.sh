#!/bin/bash
DURATION=20m
WARMUPTIME=10m
CHANGERATE=6s

##########################################################
echo "start experiment constant avg owd----------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 100ms
su -c 'cd ${SC} && ./scion.sh stop' - parallels

rm -f logs/metrics.csv
su -c 'cd ${SC} && ./scion.sh start' - parallels

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - parallels

mkdir -p experiments/logs/avgowd
cp logs/metrics.csv experiments/logs/avgowd/

##########################################################

echo "start experiment constant packet loss------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem loss 1.01017%
su -c 'cd ${SC} && ./scion.sh stop' - parallels

rm -f logs/metrics.csv
su -c 'cd ${SC} && ./scion.sh start' - parallels

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - parallels

mkdir -p experiments/logs/loss
cp logs/metrics.csv experiments/logs/loss/

##########################################################

echo "start experiment constant packet delay variation------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 100ms 15ms
su -c 'cd ${SC} && ./scion.sh stop' - parallels

rm -f logs/metrics.csv
su -c 'cd ${SC} && ./scion.sh start' - parallels

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - parallels

mkdir -p experiments/logs/variation
cp logs/metrics.csv experiments/logs/variation/

##########################################################

echo "start experiment constant packet reordering------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 20ms reorder 25% 50%
su -c 'cd ${SC} && ./scion.sh stop' - parallels

rm -f logs/metrics.csv
su -c 'cd ${SC} && ./scion.sh start' - parallels

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - parallels

mkdir -p experiments/logs/reordering
cp logs/metrics.csv experiments/logs/reordering/

##########################################################

avg_owd_var.sh $CHANGERATE $WARMUPTIME

pkt_loss_var.sh $CHANGERATE $WARMUPTIME

pkt_reordering.sh 20s $WARMUPTIME
