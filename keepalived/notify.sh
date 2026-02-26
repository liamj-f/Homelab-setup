#!/bin/bash

TYPE=$1
NAME=$2
STATE=$3

case $STATE in
  "MASTER")
    docker start rsync
    docker start nebula-sync
    docker start nginx-proxy-manager
    # Enable DHCP on local pihole
    docker exec pihole pihole -a enabledhcp
    ;;
  "BACKUP"|"FAULT")
    docker stop rsync
    docker stop nebula-sync
    docker stop nginx-proxy-manager
    # Disable DHCP on local pihole
    docker exec pihole pihole -a disabledhcp
    ;;
  *)
    logger "keepalived notify: unknown state $STATE"
    exit 1
    ;;
esac

logger "keepalived notify: transitioned to $STATE"
exit 0