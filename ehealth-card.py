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
import os
import itertools
from optparse import OptionParser
import smartcard
from smartcard.System import readers
from smartcard.ATR import ATR

def l2s(l):
	return "".join(map(lambda x: chr(x), l)).decode('utf-8')


class SmartCardCommunication:
	"""
	Handles smard card communication with ISO 7816-4.
	"""
	def __init__(self, reader, verbosity):
		self.reader = reader
		self.connection = reader.createConnection()
		self.verbosity = verbosity
		try:
			self.connection.connect()
		except smartcard.Exceptions.CardConnectionException, e:
			print e.message
			sys.exit(1)

	def get_atr(self):
		return self.connection.getATR()

	def select_file(self, file_id):
		SELECT = [0x00, 0xa4, 0x00, 0x00, len(file_id)]
		data, sw1, sw2 = self.connection.transmit(SELECT + file_id)
		if self.verbosity > 0:
			print "SELECT returned sw1 = %x, sw2 = %x" % (sw1, sw2)
		if sw1 != 0x90:
			sys.stderr.write("SELECT failed - exiting\n")
			sys.exit(1)

	def read_binary(self, length):
		READ_BINARY = [0x00, 0xb0, 0x00, 0x00, 0x00, 0x00, length]
		data, sw1, sw2 = self.connection.transmit(READ_BINARY)
		if self.verbosity > 0:
			print "READ BINARY returned sw1 = %x, sw2 = %x" % (sw1, sw2)
		if sw1 != 0x90:
			sys.stderr.write("READ BINARY failed - exiting\n")
			sys.exit(1)
		return data


class HealthCard:
	"""
	Communicate with Swiss health insurance card (eCH-0064).
	"""

	# expected answer to reset
	ATR = [0x3B, 0x9F, 0x13, 0x81, 0xB1, 0x80, 0x37, 0x1F, 0x03, 0x80, 0x31, 0xF8, 0x69, 0x4D, 0x54, 0x43, 0x4F, 0x53, 0x70, 0x02, 0x01, 0x02, 0x81, 0x07, 0x86]

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

	TLV_FORMATS = {
		'ID': [
			(0x80, 50, 's', "name"),
			(0x82,  8, 'd', "date_of_birth"),
			(0x83, 13, 's', "insurance_number"),
			(0x84,  1, 'b', "sex"),
			],
		'AD': [
			(0x90,  2, 's', "issuing_state_id"),
			(0x91, 50, 's', "insurance_name"),
			(0x92,  5, 's', "insurance_BAG_number"),
			(0x93, 20, 's', "card_number"),
			(0x94,  8, 'd', "expiry_date"),
			]
	}

	def __init__(self, reader, verbosity):
		self.scc = SmartCardCommunication(reader, verbosity)
		self.verbosity = verbosity
		atr = self.scc.get_atr()
		if not atr == self.ATR:
			sys.stderr.write("Unexpected ATR - not a Swiss health insurance card? Exiting.\n")
			sys.exit(1)
		if self.verbosity > 0:
			print "ATR: " + " ".join([hex(x) for x in atr])
		if self.verbosity > 1:
			ATR(atr).dump()

	def decode_tlv(self, tlv_format, data):
		output = {}
		offset = 0
		if options.verbosity > 1:
			print "decoding data:"
			print [hex(x) for x in data]
		if data[0] != 0x65:
			sys.stderr.write("Error: expected 0x65 as first byte of TLV data, but got %x\n" % data[0])
			return output
		offset += 2
		for entry in tlv_format:
			if data[offset] != entry[0]:
				sys.stderr.write("Error: expected %x as TLV tag for '%s', but got %x\n" % (entry[0], entry[3], data[offset]))
				return output
			offset += 1
			length = data[offset]
			if length > entry[1]:
				sys.stderr.write("Error: TLV length %d too large (max %d) for '%s'\n" % (length, entry[1], entry[3]))
				return output
			offset += 1
			if entry[2] == 's':
				output[entry[3]] = l2s(data[offset:offset+length])
			elif entry[2] == 'd':
				date = l2s(data[offset:offset+length])
				output[entry[3]] = (int(date[0:4]), int(date[4:6]), int(date[6:8]))
			else:
				output[entry[3]] = data[offset:offset+length]
			offset += length
		return output

	def decode_id(self, data):
		"""
		Decode ID (identification data) TLV.

		@param data: binary data
		"""
		output = self.decode_tlv(self.TLV_FORMATS['ID'], data)
		output['family_name'] = output['name'].split(',')[0].strip()
		output['given_name'] = output['name'].split(',')[1].strip()
		SEX = {0: 'unknown', 1: 'male', 2: 'female', 9: 'not applicable'}
		output['sex'] = SEX[output['sex'][0]]
		return output

	def decode_ad(self, data):
		"""
		Decode AD (administrative data) TLV.

		@param data: binary data
		"""
		return self.decode_tlv(self.TLV_FORMATS['AD'], data)

	def decode_version(self, data):
		"""
		Decode VERSION EF.

		@param data: binary data
		"""
		output = {}
		output['acronym'] = l2s(data[0:3])
		output['version'] = data[3] & ~0x80
		output['PDC'] = (data[3] & 0x80) == 0x80
		return output

	def print_id(self):
		self.scc.select_file(self.EF['ID'])
		data = self.decode_id(self.scc.read_binary(84))
		print "Name:                  " + data['given_name'] + " " + data['family_name']
		print "Date of birth (y-m-d): %d-%d-%d" % data['date_of_birth']
		print "Insurance number:      " + data['insurance_number']
		print "Sex:                   " + data['sex']

	def print_ad(self):
		self.scc.select_file(self.EF['AD'])
		data = self.decode_ad(self.scc.read_binary(95))
		print "Issuing state ID:     " + data['issuing_state_id']
		print "Insurance name:       " + data['insurance_name']
		print "Insurance BAG number: " + data['insurance_BAG_number']
		print "Card number:          " + data['card_number']
		print "Expiry data (y-m-d):  %d-%d-%d" % data['expiry_date']

	def print_version(self):
		self.scc.select_file(self.EF['VERSION'])
		data = self.decode_version(self.scc.read_binary(4))
		print "%s Version %d (PDC: %s)" % (data['acronym'], data['version'], data['PDC'])

	def get_cvc_pdc(self):
		# TODO make get file command generic .. (-> save lengths in EF dict)
		filename = "EF.CVC.PDC.bin"
		if os.path.exists(filename):
			sys.stderr.write("Error: file '%s' already exists\n" % filename)
			return
		self.scc.select_file(self.EF['CVC.PDC'])
		data = self.scc.read_binary(217)
		f = open(filename, 'wb')
		f.write("".join(chr(x) for x in data))
		f.close()

if __name__ == "__main__":
	parser = OptionParser(usage="%prog <cmd>", version="%prog 0.1")
	parser.add_option("-r", "--reader", type="int", dest="reader", help="use reader number N", metavar="N")
	parser.add_option("-l", "--list-readers", dest="list_readers", action="store_true", help="list available readers")
	parser.add_option("-i", "--print-id", dest="print_id", action="store_true", help="read, decode and print EF.ID")
	parser.add_option("-a", "--print-ad", dest="print_ad", action="store_true", help="read, decode and print EF.AD")
	parser.add_option("-V", "--print-version", dest="print_version", action="store_true", help="read, decode and print EF.VERSION")
	parser.add_option("",   "--get-cvc-pdc", dest="get_cvc_pdc", action="store_true", help="read and store EF.CVC.PDC")
	parser.add_option("-v", "--verbose", action="count", dest="verbosity", default=0, help="verbose output [default: %default]")
	(options, args) = parser.parse_args()

	smartcard_readers = readers()

	if options.list_readers:
		c = itertools.count()
		for reader in smartcard_readers:
			print "%s: %s" % (c.next(), reader)
		sys.exit(0)

	if options.reader:
		if options.reader >= len(smartcard_readers):
			sys.stderr.write("reader not available: %s\n" % options.reader)
			sys.exit(1)
		reader = smartcard_readers[options.reader]
	else:
		reader = smartcard_readers[0]

	hc = HealthCard(reader, options.verbosity)
	if options.print_id:
		hc.print_id()
	if options.print_ad:
		hc.print_ad()
	if options.print_version:
		hc.print_version()
	if options.get_cvc_pdc:
		hc.get_cvc_pdc()
