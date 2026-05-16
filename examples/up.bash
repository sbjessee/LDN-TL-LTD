#!/bin/bash
airmon-ng check kill
airmon-ng start wlan0
airmon-ng start wlan1
iw dev wlan0mon set channel 1  
iw dev wlan1mon set channel 1  
ethtool -K wlan1mon rx-fcs off