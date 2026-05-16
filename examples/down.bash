#!/bin/bash
airmon-ng stop wlan0mon
airmon-ng stop wlan1mon
systemctl restart NetworkManager