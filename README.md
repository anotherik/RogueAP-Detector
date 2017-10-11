# RogueAP-Detector

## Objective
Identify Rogue Access Points in a network  

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
-a active_mode		-> activates random probe requests  

Examples:  
	
	./rogue_detector.py -i iface -s iwlist -p example_profile.txt  
	./rogue_detector.pu -i iface -s iwlist  
	./rogue_detector.py -i iface -s scapy -p example_profile.txt  
	./rogue_detector.py -i iface1 -im iface2 -s iwlist -p profile.txt -a  

	./rogue_detector.py -im iface -h   

## Dependencies
python2.7  
scapy  
