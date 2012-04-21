#!/bin/bash

IP_HIT_LIMIT=30
HOST_HIT_LIMIT=20
RANGE=120
TTL=180

while [ 1 ]; do
	TIME=`date +%s`;
	mysql -e "INSERT INTO top_ips (timestamp, ip_src_addr, hits_per_sec) SELECT $TIME, ip_src_addr, CAST(COUNT(ip_src_addr)/$RANGE AS UNSIGNED) + 1 AS hits_per_sec FROM headers WHERE timestamp BETWEEN $TIME - $RANGE AND $TIME GROUP BY ip_src_addr HAVING hits_per_sec >= $IP_HIT_LIMIT  ORDER BY hits_per_sec;"
	mysql -e "INSERT INTO top_hosts (timestamp, http_host, hits_per_sec) SELECT $TIME, http_host, CAST(COUNT(ip_src_addr)/$RANGE AS UNSIGNED) + 1 AS hits_per_sec FROM headers WHERE http_host IS NOT NULL AND (timestamp BETWEEN $TIME - 60 AND $TIME) GROUP BY http_host HAVING hits_per_sec >= $HOST_HIT_LIMIT ORDER BY hits_per_sec;"
	IPLIST=`mysql -sN -e "SELECT INET_NTOA(ip_src_addr) FROM top_ips WHERE timestamp = '$TIME';"`
	for a in `echo $IPLIST`; do
		echo "/sbin/iptables -I bad-http 1 -s $a -j DROP"
		mysql -e "INSERT INTO hosts_under_attack (timestamp, http_host, ip_src_addr, hits_per_sec) SELECT $TIME, http_host, ip_src_addr, CAST(COUNT(http_host)/120 AS UNSIGNED) + 1 AS hits_per_sec FROM headers WHERE ip_src_addr = INET_ATON('$a') AND (timestamp BETWEEN $TIME - 120 AND $TIME) AND http_host IS NOT NULL GROUP BY http_host ORDER BY hits_per_sec;"
	done;
	HOSTLIST=`mysql -sN -e "SELECT http_host FROM top_hosts WHERE timestamp = '$TIME';"`
	for a in `echo $HOSTLIST`; do
		echo "$a"
	done;	
	mysql -e "DELETE FROM headers WHERE timestamp < $TIME - $TTL;"
	sleep 60;
done;
