import io         # used to create file streams
from io import open
import fcntl      # used to access I2C parameters like addresses
import random
import time       # used for sleep delay and timestamps
import string     # helps parse strings
import sys
import datetime
import json
import requests
import datetime
import hashlib
import hmac
import base64
import requests

# Update the customer ID to your Log Analytics workspace ID
customer_id = 'xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# The log type is the name of the event that is being submitted.
log_type = 'HotTub'


class AtlasI2C:
	long_timeout = 1.5         	# the timeout needed to query readings and calibrations
	default_address = 98     	# the default address for the sensor
	current_addr = default_address

	def __init__(self, address=default_address ):

		self.file_read = io.open("/dev/i2c-1", "rb", buffering=0)
		self.file_write = io.open("/dev/i2c-1", "wb", buffering=0)

		self.set_i2c_address(address)

	def set_i2c_address(self, addr):

		I2C_SLAVE = 0x703
		fcntl.ioctl(self.file_read, I2C_SLAVE, addr)
		fcntl.ioctl(self.file_write, I2C_SLAVE, addr)
		self.current_addr = addr

	def write(self, cmd):
		cmd += "\00"
		self.file_write.write(cmd.encode('latin-1'))

	def read(self, num_of_bytes=31):
		res = self.file_read.read(num_of_bytes)   # read from the board
		if type(res[0]) is str:	 # if python2 read
			response = [i for i in res if i != '\x00']
			if ord(response[0]) == 1:             # if the response isn't an error
				char_list = list(map(lambda x: chr(ord(x) & ~0x80), list(response[1:])))
				return ''.join(char_list)
			else:
				return "Error " + str(ord(response[0]))
				
		else:	# if python3 read
			if res[0] == 1: 
				char_list = list(map(lambda x: chr(x & ~0x80), list(res[1:])))
				return ''.join(char_list)
			else:
				return "Error " + str(res[0])

	def query(self):

		self.write("R")
		time.sleep(self.long_timeout)
		return self.read()

	def close(self):
		self.file_read.close()
		self.file_write.close()


		
def main():

	device = AtlasI2C()

	while True:

		currentDT = datetime.datetime.now()

		device.set_i2c_address(int(99))
		phValue = device.query()
		time.sleep(2)

		device.set_i2c_address(int(98))
		orp = device.query()
		time.sleep(2)

		device.set_i2c_address(int(102))
		temp = device.query()
		time.sleep(2)

		phValue = phValue.rstrip('\x00')
		orp = orp.rstrip('\x00')
		cTemp = temp.rstrip('\x00')
		fTemp = float(cTemp)
		jTemp = (fTemp * 9/5) + 32
		zTemp = format(jTemp, '.2f')

		json_data = {
			"PHValue": phValue,
			"ORPValue": orp,
			"TempValue": zTemp
		}

		body = json.dumps(json_data)

		try:
			post_data(customer_id, shared_key, body, log_type)
			print(json_data)
			print("Accepted")
		except:
			print("An exception occurred")

		time.sleep(2)



# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = string_to_hash.encode('utf-8')  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
	method = 'POST'
	content_type = 'application/json'
	resource = '/api/logs'
	rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
	content_length = len(body)
	signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
	uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

	headers = {
		'content-type': content_type,
		'Authorization': signature,
		'Log-Type': log_type,
		'x-ms-date': rfc1123date
	}

	try:
		response = requests.post(uri,data=body, headers=headers)
		print("Accepted")
	except:
		print("An exception occurred")

if __name__ == '__main__':
	main()
