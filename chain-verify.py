import beacon

init = beacon.get()
a = beacon.start_of_chain(init['timeStamp'])
prev = a['previousOutputValue']
ts = a['timeStamp']
end = init['timeStamp']
while ts <= end:
    ts = int(ts)+60
    b = beacon.get(ts)
    check = ""
    if not beacon.verify(a['signatureValue'], a['data']):
        check = "S"
    if not beacon.check_output(a['signatureValue'], a['outputValue']):
        check = check + "H"
    if not b['previousOutputValue'] == prev:
        check = check + "P"
    if len(check) > 0:
        print str(ts) + ": " + check
    prev = b['outputValue']
