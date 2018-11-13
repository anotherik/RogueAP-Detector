#!/usr/bin/python2
# Network monitor using iwlist
import subprocess, sys, time, re, json, os, signal
import manufacturer.parse_manufacturer as manufacturer
import modules.detectors.noknowled_detector as noknowled_detector
import modules.logs.logs_api as logs_api
import modules.detectors.passive_detectors as passive_detectors
import modules.manage_interfaces as manage_interfaces
import modules.colors as colors
import Queue, multiprocessing
from datetime import timedelta

captured_aps = []
manufacturer_table = "manufacturer/manufacturer_table.txt"
table_of_manufacturers = {}


global interface_monitor

def getTimeDate():
	return time.strftime("%X") +" "+ time.strftime("%x")#time.strftime("%c")

def getTimeDate2():
        return time.strftime("%x").replace("/", "")+"_"+time.strftime("%X")

log_name = "logs/run_"+getTimeDate2()+".log" 
log_file = open(log_name,'a')

class Unbuffered:

   def __init__(self, stream):

       self.stream = stream

   def write(self, data):

       self.stream.write(data)
       self.stream.flush()
       log_file.write(data)    # Write the data of stdout here to a text file as well

def signal_handler(signal, frame):
	try:
		manage_interfaces.disable_monitor(interface_monitor)
	except Exception, err:
		logs_api.errors_log(str(err))
		pass

	print (colors.get_color("GRAY") + "\nExiting...\nGoodbye!"+colors.get_color("ENDC"))
	sys.exit(0)

def scan(*arg):
	##print ("Scanning "+str(len(arg)))
	active_probing, profile = False, False
	interface = arg[0]
	if(len(arg)==2):
		profile = arg[1]
	elif(len(arg)==3):
		active_probing = arg[1]
		interface_monitor = arg[2]
	elif(len(arg)==4):
		profile = arg[1]
		active_probing = arg[2]
		interface_monitor = arg[3]

	global table_of_manufacturers
	table_of_manufacturers = manufacturer.MacParser(manufacturer_table).refresh()
	sys.stdout=Unbuffered(sys.stdout)
	
	table = ['Date','AP Name','CH','BSSID','Brand','Signal','Quality','Frequency','Encryption','Cipher', 'Authentication','TSF']
	print (colors.get_color("BOLD") + '{:^22s}|{:^24s}|{:^9s}|{:^19s}|{:^15s}|{:^8s}|{:^9s}|{:^11s}|{:^18s}|{:^8s}|{:^16s}|{:^16s}'.format(table[0],table[1],table[2],table[3],table[4],table[5],table[6],table[7],table[8],table[9],table[10],table[11]) + colors.get_color("ENDC"))
	while True:
		ap_list = get_results(interface)
		try:
			for line in ap_list:
				# filter to check if APs already exists 
				if filter_aps(line, profile):
					limited = False
					if len(line['essid'])>21:
						limited = True

					# apply detections heuristics
					if limited:
						if (noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_1"):
							print (colors.get_color("FAIL") + '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'][0:21],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf']) + colors.get_color("ENDC") )
						elif (noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_2" or noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_4"):
							print (colors.get_color("FAIL1") + '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'][0:21],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf']) + colors.get_color("ENDC") )
						elif (noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_3"):
							print (colors.get_color("FAIL2") + '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'][0:21],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf']) + colors.get_color("ENDC") )
						else:
							print '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'][0:21],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf'])
					else:
						if (noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_1"):
							print (colors.get_color("FAIL") + '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf']) + colors.get_color("ENDC") )
						elif (noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_2" or noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_4"):
							print (colors.get_color("FAIL1") + '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf']) + colors.get_color("ENDC") )
						elif (noknowled_detector.suspicious_behaviours(line,captured_aps) == "suspicious_3"):
							print (colors.get_color("FAIL2") + '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf']) + colors.get_color("ENDC") )
						else:
							print '{:^22s} {:<23s}  {:^9s} {:^19s} {:^15s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(),line['essid'],line['channel'],line['mac'], line['manufacturer'],line['signal'],line['quality'],line['frequency'],line['key type'],line['group cipher'], line['authentication suites'], line['tsf'])
		
					
					if(profile):
						passive_detectors.authorized_aps(line, profile)
					
					if( line['key type'] == "Open"):
						passive_detectors.free_WiFis_detect(line, captured_aps)

					passive_detectors.spot_karma(line)
					#passive_detectors.deauth_detector(interface_monitor) # new stufx
					
					if (active_probing):
						passive_detectors.spoting_PineAP(line, active_probing, interface_monitor)
					else:
						passive_detectors.spoting_PineAP(line)

					#if (deauth_detect):
						#passive_detectors.deauth_detector(interface_monitor) # new stufx
					# end of detections heuristics	

					passive_detectors.check_tsf(line)

					captured_aps.append(line)

			signal.signal(signal.SIGINT, signal_handler)
			time.sleep(1)
		except Exception, err:
			logs_api.errors_log(str(err))
			pass

def get_results(interface):
    list_of_results=[]
    try:
		#Call the process to get the output to parse
        proc = subprocess.check_output("sudo iwlist "+interface+" scan",shell=True)
		#Break the output making an array containing the info of each Access Point 
        list_of_results = re.split(r'\bCell \d{2}\b - ',proc)[1:]
    except subprocess.CalledProcessError:
    	logs_api.errors_log("Error"+str(subprocess.CalledProcessError))

    return parse(list_of_results)

def filter_aps(*arg):
	access_point = arg[0]
	profile = arg[1]
	# if profile mode is enabled filter results just for that essid
	filtered_ssid = ""
	if (profile):
		with open(profile,'r') as f:
			next(f) #skipping first line
			for line in f:
				filtered_ssid = line.split()[0]
				break

		if access_point['essid'] != filtered_ssid:
			return False

	for ap in captured_aps:
		try:
			if ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel'] and ap['key type'] == access_point['key type'] and ap['group cipher'] == access_point['group cipher'] and ( abs(int(access_point['signal'])) <= abs(int(ap['signal']))+20 and abs(int(access_point['signal'])) >= abs(int(ap['signal']))-20):
				return False
		except Exception as e: 
			logs_api.errors_log("Exception found: "+str(e))
			pass
	return True

def parse(list):
    parsed_list = []

    for network in list:
		try:
			ap={}	
			network = network.strip()
			essid=""
			address=""
			quality=""
			signal=""
			channel=""
			encryption_key=""
			key_type=""
			group_cipher=""
			pairwise_cipher=""
			authentication_suites=""
			tsf=""
			frequency=""
			
			#Get Frequency
			match = re.search('Frequency:(\S+)', network)
			if match: 
			    frequency = match.group(1)
			    ap.update({"frequency":frequency})

			#Get the TSF
			match = re.search('Extra:tsf=(\S+)', network)
			if match:
				tsf = match.group(1)
				i = int(tsf, 16)
				tsf = str(timedelta(microseconds=i))[:-4]
				ap.update({"tsf":tsf})

			#Get the name of the AP 
			match = re.search('ESSID:"(([ ]*(\S+)*)*)"',network)
			if match: 
			    essid = match.group(1)
			    ap.update({"essid":essid})
			
			#Get the BSSID of the AP
			match = re.search('Address: (\S+)',network)
			if match: 
			    address = match.group(1)
			    ap.update({"mac":address})

			#Get the Channel of the AP 
			match = re.search('Channel:(\S+)',network)
			if match: 
			    channel = match.group(1)
			    ap.update({"channel":channel})

			#Find the brand of the AP    
			global table_of_manufacturers
			manufacturer_data = manufacturer.search(table_of_manufacturers,str(address))
			if(len(manufacturer_data)>0):
				ap.update({"manufacturer":manufacturer_data[0].manuf})
				ap.update({"comment":manufacturer_data[0].comment})
			else: 	
				ap.update({"manufacturer":"Null"})
				ap.update({"comment":"Null"})

			#Get the quality of the signal and the signal level 
			match = re.search('Quality=(\d+/\d+)  Signal level=(-\d+) dBm',network)
			if match: 
			    quality = match.group(1)
			    a = quality[0:2]
			    b = quality[3:5]
			    quality_calc = format((float(a)/float(b)), '.2f')
			    signal = match.group(2)
			    ap.update({"quality":quality})
			    ap.update({"quality_calc":quality_calc})
			    ap.update({"signal":signal})		
			
			#Check if there is an Encryption key on the AP
			match = re.search('Encryption key:(\S+)',network)
			if match: 
			    encryption_key = match.group(1)
			    ap.update({"encryption":encryption_key})
			
			#Find the encryption type (WEP, WPA, WPA2 or Open)
			match = re.search(r'(?<=802.11i/)[a-zA-Z0-9_ ]*',network)
			if match and match != "Unknown" and match != "IEEE 802":
			    key_type=match.group(0)
			    ap.update({"key type":key_type})	        
			elif ap['encryption']=='on':
			    key_type="WEP"
			    ap.update({"key type":key_type})
			else:
			    key_type="Open"
			    ap.update({"key type":key_type})
			
			#Get the Cipher being used
			match = re.search(r'Group Cipher : ([a-zA-Z0-9_ ]*)',network)
			if match:
			    group_cipher=match.group(1)	        
			    ap.update({"group cipher":group_cipher})	
			elif ap['encryption']=='on':
			    group_cipher="WEP"
			    ap.update({"group cipher":group_cipher})	
			else:
			    group_cipher=""
			    ap.update({"group cipher":group_cipher})	
			
			#Get the Pairwise Cipher being used	
			match = re.search('Pairwise Ciphers ([(\d+)]*) : ([a-zA-Z0-9_ ]*)',network)
			if match:
			    pairwise_cipher=match.group(2)
			    ap.update({"pairwise cipher":pairwise_cipher})    
			elif ap['encryption']=='on':
			    pairwise_cipher="WEP"
			    ap.update({"pairwise cipher":pairwise_cipher})	
			else:
			    pairwise_cipher=""
			    ap.update({"pairwise cipher":pairwise_cipher})

			#Get the Authentication Suites
			match = re.search('Authentication Suites ([(\d+)]*) : ([a-zA-Z0-9_ ]*)',network)
			if match:
				authentication_suites=match.group(2)	    
				ap.update({"authentication suites":authentication_suites})	
			elif ap['encryption']=='on':
			    authentication_suites=""
			    ap.update({"authentication suites":authentication_suites})
			else:
			    authentication_suites=""
			    ap.update({"authentication suites":authentication_suites})
			
			parsed_list.append(ap)	 
		except:
			pass

    return parsed_list
