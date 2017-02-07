#!/usr/bin/python2

import mac_finder.manuf as manuf
import manipulate_db


vendor_finder = manuf.MacParser(manuf_table)
conn = manipulate_db.open_db(dbname)


def scan(iface):

	table = ['Network Name','MAC Address', 'Channel','Signal','Quality','Encryption','Cipher', 'Pairwise','Authentication', 'Manufacturer', 'Comment']
	print '{:^22s}|{:^19s}|{:^9s}|{:^8s}|{:^9s}|{:^16s}|{:^8s}|{:^11s}|{:^16s}|{:^14s}|{:^14s}'.format(table[0],table[1],table[2],table[3],table[4],table[5],table[6],table[7],table[8],table[9], table[10])

	while 1:
		
		access_points = find_aps(iface)
		try:
