#!/usr/bin/python2
# anotherik

# Script to check system infos

import platform

def infos():
	print ("###################")
	print ("#   Your System:  #")
	print ("###################\n")
	print (" " + platform.system())
	print (" " + platform.release())
	print (" " + platform.version())
	print (" " + platform.platform())
	print ("\n###################")
	
infos()