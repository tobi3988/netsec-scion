#!/bin/bash

while :
do
    su -c 'cd ${SC} && ./scion.sh status | grep EXIT' - parallels >> status.log
    sleep 10s
done

