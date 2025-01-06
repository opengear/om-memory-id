#!/usr/bin/python3

# memory_id_v4.py
# Opengear Solution Engineering
# Jira: SLE-284
# Updated 18 December 2024 by M.Witmer
#
# Detects bad memory module SP004GISLU160NH0 for Operations Manager

import os
import fcntl
import struct
import array
import subprocess
import time
import json
import requests

# Suppresses InsecureRequestWarning for 
# Uncomment the following 2 lines if using self signed SSL certs 
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# SLE-284 Bad memory being looked for
badMemory = "SP004GISLU160NH0"

# Memory info 
I2C_SMBUS_READ = 1
I2C_SMBUS_BYTE_DATA = 2
I2C_FUNC_SMBUS_READ_BYTE_DATA = 0x00080000

# SLE-235: Create api token (SLE-284 removes ogcli dependency)
def createToken():

    cli_session_binary = "/usr/libexec/cli-session"
	
    token = subprocess.run([cli_session_binary], stdout=subprocess.PIPE).stdout.decode('utf-8').strip()

	# store token in var header
    headers = { "Authorization" : "Token " + token }

    return headers

# SLE-235: Get system model and firmware version	
def getInfo():
    
    # call createToken() to get api token
    headers = createToken()
    
    # Set up api gets
    serial = requests.get('https://localhost/api/v2/system/serial_number', headers=headers, verify=False)
    model = requests.get('https://localhost/api/v2/system/model_name', headers=headers, verify=False)
    
    # Get data & convert json into dictionaries
    s = json.loads(serial.text)['system_serial_number']['serial_number']
    m = json.loads(model.text)['system_model_name']['model_name']

    # Print output
    print('\nSystem Info')
    print(f'Serial: {s}')
    print(f'Model: {m}\n')


def smbus_read_byte_data(fd, command):
	smbus = array.array("B", struct.pack("BH32s", 0, 0, bytearray(32)))
	s = struct.pack("BBIP", I2C_SMBUS_READ, command, I2C_SMBUS_BYTE_DATA, smbus.buffer_info()[0])
	fcntl.ioctl(fd, 0x0720, s, True)
	data = struct.unpack("BBIP", s)
	byte, word, block = struct.unpack("BH32s", smbus)
	return byte & 0xff


def i2c_funcs(fd):
	# funcs support
	buf = array.array("I", [0])
	fcntl.ioctl(fd, 0x0705, buf, True)
	return buf[0]


def i2c_address(fd, address):
	fcntl.ioctl(fd, 0x0703, address, True)

# Dump output of memory into a text file
def dump_spd(address):
	fd = os.open("/dev/i2c-0", os.O_RDWR)

	if i2c_funcs(fd) & I2C_FUNC_SMBUS_READ_BYTE_DATA == 0:
		raise Exception("Missing smbus i2c support")

	i2c_address(fd, address)

	for i in range(0, 256, 16):
		dataline = ""
		characters = ""

		for j in range(0, 16):
			data = smbus_read_byte_data(fd, i + j)

			dataline += " {:02x}".format(data)
			characters += chr(data) if data >= ord(" ") and data <= ord("~") else "."

		#print("{:02x}:{} {}".format(i, dataline, characters))

		# write dump to a temp file
		with open ("temp.txt", "a+") as f:
			f.write("{:02x}:{} {}\n".format(i, dataline, characters))
			f.close()

	os.close(fd)

# SLE-284: Added check versus badMemory
def checkMemory():

	count = 0

	print(f"Looking for {badMemory}...\n")

	time.sleep(2)

	print("Memory Info")

	with open("temp.txt", "r") as g:
		for line in g:
			if "80:" in line:
				print(f"{line.strip()}")
			if badMemory in line:
				count += 1

	if count != 0:
		print(f"\n*** {count} of {badMemory} found!\n")
		print("*** Replacement of memory modules recommmended! ***\n")
	else:
		print(f"\n{badMemory} not found.\n")
		print(f"Memory modules are fine. No replacement memory modules needed.\n")

    # delete temp.txt
	os.system('rm temp.txt')
				

if __name__ == "__main__":
	
    getInfo()

	# dimm-0 0x50
    # dimm-1 0x51
    for index in range(2):
        try:
            dump_spd(0x50 + index)
            #print()
        except:
            print()
            #print(" - No Dimm?")

    checkMemory()
