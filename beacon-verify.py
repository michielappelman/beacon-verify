# Verify the NIST beacon
# Michiel Appelman <michiel@appelman.se>

import sys
import time
import OpenSSL
import hashlib
import requests
import xml.etree.ElementTree as ET
from optparse import OptionParser

record_url = 'https://beacon.nist.gov/rest/record/'

usage = "Usage: %prog [options] [timestamp]"
parser = OptionParser(usage)
parser.add_option("-c", "--cert", dest="cfile", metavar="CERT",
                  help="read certificate from CERT", default='./beacon.cer')
parser.add_option("-v", "--verbose", dest="verbose", action="store_true",
                  help="be more verbose, otherwise only errors are printed")
(options, args) = parser.parse_args()

if len(args) > 1:
    parser.error("Too many arguments, taking only one timestamp!")
    sys.exit(1)
if len(args) == 0:
    if options.verbose:
        print "No timestamp provided, checking latest beacon."
    ts = "last"
if len(args) == 1:
    try:
        int(args[0])+1
    except:
        parser.error("Timestamp is not an integer.")
        sys.exit(1)
    if int(args[0]) < 1378395540 and options.verbose:
        print "The first available beacon is at 1378395540, using that."
    ts = args[0]

# Load the correct public key using a non-automated method. Make sure it's 
# read-only for extra paranoia.
try:
    cert_file = open(options.cfile, 'r').read()
except:
    print "Certificate file \"" + options.cfile + "\" could not be read, \
you can get it from https://beacon.nist.gov/home"
    sys.exit(1)
beacon_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, \
    cert_file)

# Load the record from one-minute ago in a beacon-dict.
record = requests.get(record_url + ts, verify=True)
xml = ET.fromstring(record.content)
beacon={}
for child in xml:
    beacon[child.tag] = child.text

if options.verbose:
    print "Timestamp: " + beacon['timeStamp']
    print "Output Value: " + beacon['outputValue']

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
if options.verbose:
    print "Beacon signature verification passed."

# Hash the provided, validated signature.
sign_hash = hashlib.sha512(beacon['signatureValue'].decode("hex")).hexdigest().upper()

if sign_hash != beacon['outputValue']:
    print "Signature hash does not match Output Value."
    sys.exit(1)
if options.verbose:
    print "Signature hash successfully matches Output Value."
