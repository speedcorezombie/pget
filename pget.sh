#!/bin/bash
#. /etc/rc.d/init.d/functions

start() {
	./pget -d eth0 -n 188.93.212.0/24 -x 188.93.208.0/21
}

stop() {
	kill `cat /var/run/pget.pid`
}

case "$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  restart)
        stop
        start
        ;;
esac
