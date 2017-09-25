#!/usr/bin/python2
# -*- coding: utf-8 -*-
# author: anotherik (Ricardo Gonçalves)

import sqlite3

# create/open a (new) database inside the folder data
def open_db(): # dbname
	conn = sqlite3.connect(":memory:") # ":memory:" to store databse in memmory - 'data/'+dbname+'.db'
	#print("Opened database successfully")
	return conn

# create a table inside the chosen database for the scanned Access Points (APs)
def create_table(conn): #, dbname
	conn.execute('''CREATE TABLE APs
       (ID INT PRIMARY KEY     NOT NULL,
       SSID           CHAR(50),
       BSSID          CHAR(50),
       CHANNEL        INT,
       SIGNAL         INT,
       Quality        INT,
       Encryption     CHAR(50),
       Cipher         CHAR(50),
       Pairwise       CHAR(50),
       Authentication CHAR(50),
       Manufacturer   CHAR(50));''')

	#print("APs table created successfully")


# create a table inside the chosen database for the scanned Access Points (APs)
def create_table_scapy(conn): #, dbname
       conn.execute('''CREATE TABLE APs
       (ssid           CHAR(50),
       bssid          CHAR(50),
       channel        INT,
       manufacturer   CHAR(50),
       encryption     CHAR(50));''')

       #print("Scapy APs table created successfully")

# insert values in the table APs of the chosen database
def insert_in_db(conn, ssid, bssid, ch, signal, quality, encryption, cipher, pairwise, authentication, manufacturer):
	conn.execute("insert into APs (ssid, bssid, ch, signal, quality, encryption, cipher, pairwise, authentication, manufacturer) values (?,?,?,?,?,?,?,?,?,?)", (ssid, bssid, ch, signal, quality, encryption, cipher, pairwise, authentication, manufacturer))
	conn.commit()

# insert values in the table APs of the chosen database
def insert_in_db_scapy(conn, ssid, bssid, ch, manufacturer, encryption):
       conn.execute("insert into APs (ssid, bssid, channel, manufacturer, encryption) values (?,?,?,?,?)", (ssid, bssid, ch, manufacturer, encryption))
       conn.commit()

def select_from_db(conn):
       cur = conn.cursor()
       cur.execute("select * from APs")
       for row in cur:
              print row

       conn.close()

#db_name = raw_input("Enter the name for the database: ")
#open_db(db_name)
#create_table(db_name)