# RogueAP-Detector

## Objective
Detect Rogue Access Points

## Rogue Access Point Detector

	Detectors Module: Set of passive detectors to identify RogueAP types  
	Actuators Module: Set of active detectors to identify RogueAP types  
	Scanners  Module: Methods to scan the network  

## Usage
./rogue_detector.py [option]  

Options:  

	-i interface		-> interface to monitor the network  
	-im interface		-> interface for active mode  
	-p profile              -> name of the profile to load  
	-s scan_type            -> name of scanning type (iwlist, scapy)  
	-h hive_mode		-> creates an AP  
	-d deauth               -> deauthenticates users from target AP  
	-deauth_detect          -> detects deauthentication attacks  
	-a active_mode		-> activates random probe requests  

Examples:  

	# Scan for RAP without a profile - using iwlist
	./rogue_detector.py -i iface -s iwlist  
	# Scan for RAPs using a profile - using iwlist  
	./rogue_detector.py -i iface -s iwlist -p example_profile.txt  
	# Scan for RAPs using a profile - using scapy  
	./rogue_detector.py -i iface -s scapy -p example_profile.txt  
	# Scan for RAPs using a profile and using active mode - iwlist  
	./rogue_detector.py -i iface1 -im iface2 -s iwlist -p profile.txt -a  

	# Create a RAP  
	./rogue_detector.py -im iface -h  
	# Deauthenticate mode  
	./rogue_detector.py -im iface -d  
	# Deauthentication attacks detection  
	./rogue_detector.py -im iface -deauth_detect

## Dependencies
python2.7  
scapy  
wireless-tools  
iw  

To install the dependencies, run: **./dependencies.sh**  
