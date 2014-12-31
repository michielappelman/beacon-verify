# Verify the NIST beacon
# Michiel Appelman <michiel@appelman.se>

import sys
import time
import OpenSSL
import hashlib
import requests
import xml.etree.ElementTree as ET

record_url = 'https://beacon.nist.gov/rest/record/'

# Load the correct public key using a non-automated method. Make sure it's 
# read-only for extra paranoia.
try:
    cert_file = open('./beacon.cer', 'r').read()
except:
    print "Certificate file \"beacon.cer\" could not be found, please get it \
from https://beacon.nist.gov/home"
    sys.exit(1)
beacon_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, \
    cert_file)

# Load the record from one-minute ago in a beacon-dict.
curr_ts = str(int(time.time())-60)
record = requests.get(record_url + curr_ts, verify=True)
xml = ET.fromstring(record.content)
beacon={}
for child in xml:
    beacon[child.tag] = child.text

# Compose the data to be signed.
data = beacon['version'] + \
    "{0:08x}".format(int(beacon['frequency'])).decode("hex") + \
    "{0:016x}".format(int(beacon['timeStamp'])).decode("hex") + \
    beacon['seedValue'].decode("hex") + \
    beacon['previousOutputValue'].decode("hex") + \
    "{0:08x}".format(int(beacon['statusCode'])).decode("hex")

# Convert from LE to BE because the NIST Beacon signature is created on MSWin.
rev_sign = beacon['signatureValue'].decode("hex")[::-1]

# Check if the signature matches.
try:
    OpenSSL.crypto.verify(beacon_cert, rev_sign, data, 'sha512')
except OpenSSL.crypto.Error:
    print "Beacon signature verification failed."
    sys.exit(1)

# Hash the provided, validated signature.
sign_hash = hashlib.sha512(beacon['signatureValue'].decode("hex")).hexdigest().upper()

if sign_hash != beacon['outputValue']:
    print "Signature hash does not match Output Value"
    sys.exit(1)
