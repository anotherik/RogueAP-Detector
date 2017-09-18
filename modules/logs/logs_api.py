import time, os, sys

def getDate():
	return time.strftime("%X") +" "+ time.strftime("%x")

def errors_log(error):

	if(os.path.isfile("error_log.txt")):
		with open("error_log.txt", "r") as f:
			if error not in f.read():
				with open("error_log.txt", "a") as f2:
					f2.write(getDate()+":"+error+"\n")
	else:
		with open("error_log.txt", "a") as f:
			f.write(getDate()+":"+error+"\n")
