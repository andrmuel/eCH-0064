#!/usr/bin/env python
# coding: utf-8
#
# Andreas Müller, 2012
# am@0x7.ch
#
# This code may be freely used and distributed under GNU GPL conditions.

"""
Communicate with Swiss eHealth cards as specified by eCH-0064.
"""

import sys
import itertools
from optparse import OptionParser
from smartcard.System import readers

# master file
MF = [0x3f, 0x00]

# dedicated files
DF = {
	'NOT': [0xDF, 0x01], # emergency data
	'PKCS15': [0xDF, 0x02] # PKCS#15 data
}

# elementary files
EF = {
	# main directory
	'DIR':                     [ 0x2F, 0x00],
	'ATR':                     [ 0x2F, 0x01],
	'ICCSN':                   [ 0x2F, 0x05],
	'PIN1':                    [ 0x00, 0x11],
	'PIN2 ':                   [ 0x00, 0x12],
	'PUK':                     [ 0x00, 0x14],
	'ID':                      [ 0x2F, 0x06],
	'AD':                      [ 0x2F, 0x07],
	'VERSION':                 [ 0x56, 0x00],
	'CVC.PDC':                 [ 0x2F, 0x03],
	'CVC.CA_ORG_PDC':          [ 0x2F, 0x08],
	'PrK.SB ':                 [ 0x00, 0x15],
	'CVC.CA_ROOT_VK':          [ 0x2F, 0x04],
	'PuK.CA_ROOT_VK':          [ 0x00, 0x1C],
	'C2CSTATE':                [ 0x00, 0x1D],
	'GPKeys':                  [ 0x00, 0x01],
	# emergency data directory
	'BGTD':                    [ 0xDF, 0x01, 0x1F, 0x01],
	'IMMD':                    [ 0xDF, 0x01, 0x1F, 0x02],
	'TPLD':                    [ 0xDF, 0x01, 0x1F, 0x03],
	'KHUF':                    [ 0xDF, 0x01, 0x1F, 0x04],
	'ZUSE':                    [ 0xDF, 0x01, 0x1F, 0x05],
	'MEDI':                    [ 0xDF, 0x01, 0x1F, 0x06],
	'ALLG':                    [ 0xDF, 0x01, 0x1F, 0x07],
	'ADDR':                    [ 0xDF, 0x01, 0x1F, 0x08],
	'VERF':                    [ 0xDF, 0x01, 0x1F, 0x09],
	'CIAInfo':                 [ 0xDF, 0x02, 0x50, 0x32],
	'OD':                      [ 0xDF, 0x02, 0x50, 0x31],
	'PrKD':                    [ 0xDF, 0x02, 0x1F, 0x01],
	'PuKD':                    [ 0xDF, 0x02, 0x1F, 0x02],
	'CD':                      [ 0xDF, 0x02, 0x1F, 0x03],
	'DCOD':                    [ 0xDF, 0x02, 0x1F, 0x04],
	'AOD':                     [ 0xDF, 0x02, 0x1F, 0x05],
	'CERT':                    [ 0xDF, 0x02, 0x1F, 0x06],
	'PuK.DEC':                 [ 0xDF, 0x02, 0x1F, 0x07],
	'PuK.X509':                [ 0xDF, 0x02, 0x1F, 0x08],
	'PrK.DEC':                 [ 0xDF, 0x02, 0x00, 0x16],
	'PrK.X509':                [ 0xDF, 0x02, 0x00, 0x17]
}

if __name__ == "__main__":
	parser = OptionParser(usage="%prog <cmd>", version="%prog 0.1")
	parser.add_option("-r", "--reader", type="int", dest="reader", help="use reader number N", metavar="N")
	parser.add_option("-l", "--list-readers", dest="list_readers", action="store_true", help="list available readers")
	parser.add_option("-f", "--file", dest="filename", help="write report to FILE", metavar="FILE")
	parser.add_option("-v", "--verbosity", action="count", dest="verbose", default=0, help="verbose output [default: %default]")
	(options, args) = parser.parse_args()

	if options.list_readers:
		c = itertools.count()
		for reader in readers():
			print "%s: $s" % (c.next(), reader)
		sys.exit(0)

	if options.reader:

	c = r.createConnection()
	c.connect()
	SELECT = [0x00, 0xa4, 0x00, 0x00, 0x02]
	data, sw1, sw2 = c.transmit(SELECT + EF['ID'])
	print "%x %x" % (sw1, sw2)
	READ_BINARY = [0x00, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x54]
	data, sw1, sw2 = c.transmit(READ_BINARY)
	print "%x %x" % (sw1, sw2)
	name_length = data[3]
	name = data[4:4+name_length]
	print "".join(map(lambda x: chr(x), name)).decode('utf-8')

