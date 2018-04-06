#!/bin/bash

if (( $# != 1)); then
    echo "requires the container name and the ip address in cidr notation"
    exit 1
fi

cname=$1

echo "Running pre-setup for container $cname"
echo -n "Checking if iptables is installed"
$(which iptables >/dev/null 2>&1)
if [ $? != 0 ]; then
    echo "Please install iptables and try again."
    exit 20
fi
echo -n " OK"; echo
echo -n "Checking if iproute2 is installed"
has_iproute=$(echo $(ip -V) | grep -c iproute2)
if [ $has_iproute != 1 ]; then
    echo "Please install iproute2 and try again."
    exit 21
fi
echo -n " OK"; echo
echo -n "Configuring the bridge if not done yet"
has_bridge=$(echo $(ip link show type bridge) | grep -c "cbr:")
if [ $has_bridge != 1 ]; then
    $(ip link add name cbr type bridge)
    if [ $? != 0 ]; then
        echo "Failed to create bridge."
        exit 22 
    else
        $(ip addr add 172.20.0.1/16 dev cbr)
        if [ $? != 0 ]; then
            echo "Failed to set ip address for cbr."
            exit 23
        fi
        $(ip link set dev cbr up)
        if [ $? != 0 ]; then
            echo "Failed to set cbr to up."
            exit 24
        fi
    fi
fi
echo -n " OK"; echo
echo -n "Configuring iptables to allow container traffic."
has_inner_traffic=$(iptables -S | grep -c '\-A FORWARD \-i cbr \-o cbr \-j ACCEPT')
if [ $has_inner_traffic != 1 ]; then
    $(iptables -A FORWARD -i cbr -o cbr -j ACCEPT)
    if [ $? != 0 ]; then
        echo "Failed to apply iptables rule to allow container traffic."
        exit 25
    fi
fi
echo -n " OK"; echo
echo -n "Configuring iptables to allow container to access internet."
has_internet_traffic=$(iptables -t nat -S | grep -c '\-A POSTROUTING \-s 172.20.0.0/16 \! \-o cbr \-j MASQUERADE')
if [ $has_internet_traffic != 1 ]; then
    $(iptables -t nat -A POSTROUTING -s 172.20.0.0/16 ! -o cbr -j MASQUERADE)
    if [ $? != 0 ]; then
        echo "Failed to apply iptables rule to allow internet access."
        exit 25
    fi
fi
echo -n " OK"; echo
echo -n "Configuring veth pair."
$(ip link add b${cname} type veth peer name c${cname})
if [ $? != 0 ]; then
    echo "Failed to add veth pair."
    exit 26
fi
$(ip link set dev b${cname} master cbr)
if [ $? != 0 ]; then
    echo "Failed to set master for b${cname}."
    exit 27
fi
$(ip link set b${cname} up)
if [ $? != 0 ]; then
    echo "Failed to set b${cname} to up."
    exit 28
fi
echo -n " OK"; echo

