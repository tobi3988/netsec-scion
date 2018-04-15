#!/bin/bash
DURATION=30m
WARMUPTIME=10m
CHANGERATE=1s

##########################################################
echo "start experiment constant avg owd----------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 100ms
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/avgowd
cp logs/metrics.csv experiments/logs/avgowd/
cp logs/multipath.csv experiments/logs/avgowd/

##########################################################

echo "start experiment constant packet loss------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem loss 1.01017%
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/loss
cp logs/metrics.csv experiments/logs/loss/
cp logs/multipath.csv experiments/logs/loss/

##########################################################

echo "start experiment constant packet delay variation------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 100ms 15ms
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

rm -f logs/metrics.csv
rm -f logs/multipath.csv
su -c 'cd ${SC} && ./scion.sh start' - ubuntu

sleep $DURATION
su -c 'cd ${SC} && ./scion.sh stop' - ubuntu

mkdir -p experiments/logs/variation
cp logs/metrics.csv experiments/logs/variation/
cp logs/multipath.csv experiments/logs/variation/

##########################################################

echo "start experiment constant packet reordering------------------------------"
tc qdisc del dev lo root netem
tc qdisc add dev lo root netem delay 20ms reorder 5.556% 50%
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

sh ./avg_owd_var.sh 12s $WARMUPTIME #100

sh ./pkt_loss_var.sh 38s $WARMUPTIME #30

sh ./pkt_reordering.sh 24s $WARMUPTIME #50

sh ./delay_variation_var.sh 24s $WARMUPTIME #50

tc qdisc del dev lo root netem
