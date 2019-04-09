#!/bin/sh

STAT_FILE=/home/qinpan/src/tmp/sjwxd/sjwxds_total.csv

echo -n `date` >> $STAT_FILE
echo -n "," >> $STAT_FILE
echo -n `sjwxds_ctl total | awk -F '[' '{print $2}' | awk -F ']' '{print $1}'` >> $STAT_FILE
echo -n "," >> $STAT_FILE
echo `free | sed -n 2p | awk '{print $4","$7}'` >> $STAT_FILE
