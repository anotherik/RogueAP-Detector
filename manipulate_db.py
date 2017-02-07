#!/usr/bin/python2
# author: anotherik (Ricardo Gonçalves)

import sqlite3

# create/open a (new) database inside the folder data
def open_db(dbname):
	conn = sqlite3.connect('data/'+dbname+'.db')
	print("Opened database successfully")
	return conn

# create a table inside the chosen database for the scanned Access Points (APs)
def create_table(conn, dbname):
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

	print("APs table created successfully")
	conn.close()


# insert values in the table APs of the chosen database
def insert_in_db(conn, ssid, bssid, ch, signal, quality, encryption, cipher, pairwise, authentication, manufacturer):
	conn.execute("insert into APs (ssid, bssid, ch, signal, quality, encryption, cipher, pairwise, authentication, manufacturer) values (?,?,?,?,?,?,?,?,?,?)", (ssid, bssid, ch, signal, quality, encryption, cipher, pairwise, authentication, manufacturer))
	conn.commit()

#db_name = raw_input("Enter the name for the database: ")
#open_db(db_name)
#create_table(db_name)