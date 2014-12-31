# Verify the NIST beacon
# Michiel Appelman <michiel@appelman.se>

import time
import OpenSSL
import requests
import xml.etree.ElementTree as ET

# Load the correct public key using a non-automated method. Make sure it's 
# read-only for extra paranoia.
beacon_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, \
    open('./beacon.cer','r').read())
record_url = 'https://beacon.nist.gov/rest/record/'
curr_ts = str(int(time.time())-60)

# Load the record from one-minute ago in a beacon-dict.
record = requests.get(record_url + curr_ts, verify=True)
xml = ET.fromstring(record.content)
beacon={}
for child in xml:
    beacon[child.tag] = child.text

# Compose the data to be signed.
sign_input = beacon['version'] + \
    "{0:08x}".format(int(beacon['frequency'])).decode("hex") + \
    "{0:016x}".format(int(beacon['timeStamp'])).decode("hex") + \
    beacon['seedValue'].decode("hex") + \
    beacon['previousOutputValue'].decode("hex") + \
    "{0:08x}".format(int(beacon['statusCode'])).decode("hex")

# Convert from LE to BE because the NIST Beacon signature is created on MSWin.
rev_sign = beacon['signatureValue'].decode("hex")[::-1]

# Check if the signature matches.
try:
    OpenSSL.crypto.verify(beacon_cert, rev_sign, sign_input, 'sha512')
except OpenSSL.crypto.Error:
    print "Beacon signature verification failed."
