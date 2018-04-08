#!/bin/bash

if (( $# != 2)); then
    echo "requires the child pid and nsname"
    exit 1
fi

child_pid=$1
cname=$2
for i in $(find /sys/fs/cgroup/ -mindepth 1 -maxdepth 1 -type d | egrep -v cpuset)
do
    mkdir -p ${i}/${cname}
    echo "$child_pid" > ${i}/${cname}/cgroup.procs
done

