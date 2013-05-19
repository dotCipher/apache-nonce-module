#!/bin/bash
interval=$1
pid=$2

logfile=$pid'_usage.log'

while true; do ps o pcpu,rsz -p $pid | tail -n1 >> $logfile; sleep $interval; done
