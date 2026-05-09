#!/bin/bash
airmon-ng check kill
airmon-ng start wlan0
iw dev wlan0mon set channel 1  
ethtool -K wlan0mon rx-fcs off