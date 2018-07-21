#!/usr/bin/python2

import platform

def infos():
	print platform.system()
	print platform.release()
	print platform.version()
	print platform.platform()
	
infos()