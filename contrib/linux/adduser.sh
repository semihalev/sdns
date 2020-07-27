#!/bin/sh

groupadd --system sdns
useradd --system -d /var/lib/sdns -s /usr/sbin/nologin -g sdns sdns
mkdir -p /var/lib/sdns
chown sdns:sdns /var/lib/sdns
