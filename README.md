# RogueAP Detector

_rogueAP Detector_ is an open source tool to detect Wi-Fi Rogue Access Points, covering the most commonly known attacks.  This tool is a modular framework composed of Scanners, Detectors and Actuators, which are responsible for scanning for available APs, apply a set of heuristics to detect them, and apply a defensive mechanism.  

![RogueAP Detector_1](imgs/img_1.PNG)

## Modules
<pre>
<b>Scanners</b>: Methods to scan the network  
<b>Detectors</b>: Set of passive detectors to identify RogueAP types  
<b>Actuators</b>: Set of active detectors to identify RogueAP types  
</pre>

## Usage
./rogueAP_detector.py <options>  

Options:  

	-i interface		-> interface to monitor the network  
	-im interface		-> interface for active mode  
	-p profile              -> name of the profile to load  
	-s scan_type            -> name of scanning type (iwlist, scapy)  
	-h hive_mode		-> creates an AP (configured in profiles/rogueAP.txt) 
	-d deauth               -> deauthenticates users from target AP  
	-wifi_attacks_detect    -> detects deauthentication and pmkid attacks  
	-a active_mode		-> activates random probe requests  

Examples:  

<pre>
<b> Scan for RAPs without a profile - (iwlist mode)</b>  
./rogueAP_detector.py -i iface -s iwlist  

<b> Scan for RAPs using a profile - (iwlist mode)</b>  
./rogueAP_detector.py -i iface -s iwlist -p example_profile.txt  

<b> Scan for RAPs using a profile - (scapy mode)</b>  
./rogueAP_detector.py -i iface -s scapy -p example_profile.txt  

<b> Scan for RAPs with karma detect active mode enabled - (iwlist mode)</b>  
./rogueAP_detector.py -i iface1 -im iface2 -s iwlist -a  

<b> Scan for RAPs using a profile and karma detect active mode enabled - (iwlist mode)</b>  
./rogueAP_detector.py -i iface1 -im iface2 -s iwlist -p profile.txt -a  

<b> Create a RAP</b>  
./rogueAP_detector.py -im iface -h  

<b> Deauthenticate defensive mechanism mode</b>  
./rogueAP_detector.py -im iface -d  

<b> Deauthentication and PMKID attacks detection</b>  
./rogueAP_detector.py -im iface -wifi_attacks_detect  
</pre>

Detecting Evil Twin, Multi-Channel, Different Encryption and Recently Created Rogue APs:  

![RogueAP Detector_2](imgs/img_2.PNG)

Validate Free WiFis and Detecting Karma Attacks:  

![RogueAP Detector_3](imgs/img_3.PNG)

PMKID Attack Detection:  

![RogueAP Detector_4](imgs/img_4.PNG)

PMKID and Deauthentication Attacks Detection:  

![RogueAP Detector_5](imgs/img_5.PNG)

## Dependencies
python2.7  
scapy  
wireless-tools  
iw  

To install the dependencies, run: **./dependencies.sh**  
