import time, os, sys

def getDate():
	return time.strftime("%X") +" "+ time.strftime("%x")

def errors_log(error):

	if(os.path.isfile("logs/errors.log")):
		with open("logs/errors.log", "r") as f:
			if error not in f.read():
				with open("logs/errors.log", "a") as f2:
					f2.write(getDate()+":"+error+"\n")
	else:
		with open("logs/errors.log", "a") as f:
			f.write(getDate()+":"+error+"\n")
