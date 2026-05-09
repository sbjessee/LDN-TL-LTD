#!/bin/bash
# Kill NetworkManager and wpa_supplicant so they don't interfere with LDN.
# LDN creates its own ldn (AP) and ldn-mon (monitor) interfaces via nl80211.
airmon-ng check kill
