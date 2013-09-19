#!/usr/bin/python

import binascii
import base64
import collections
import sys
import string

# Conversion Methods
def hextobase64(hexstring):
	return base64.b64encode(binascii.a2b_hex(hexstring))

def base64tohex(base64string):
	return binascii.b2a_hex(base64.b64decode(base64string))

def set1():
	h = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	assert(h == base64tohex(b))
	assert(b == hextobase64(h))
	
set1()

def fixed_xor(buf1, buf2):
	# first letter of each wrod, turn to ints, xor together.
	# ob = hex(int(buf1, 16) ^ int(buf2, 16))
	# 
	return ''.join([chr(x ^ y) for x,y in zip(bytearray(buf1), bytearray(buf2))])

def set2():
	b1 = binascii.a2b_hex("1c0111001f010100061a024b53535009181c")
	b2 = binascii.a2b_hex("686974207468652062756c6c277320657965")
	xorsum = "746865206b696420646f6e277420706c6179"

	assert(binascii.b2a_hex(fixed_xor(b1, b2)) == xorsum)

set2()


def single_xor(binarystring, xor_char):
	'''pass in ct eventualy'''
	

	# brute = []
	# for i in xrange(255):
	# 	brute.append(chr(i))
	# # #  # Return Binar XOR
	# 	print brute[i]*len(binarystring)
	# # #return fixed_xor(ct, brute[10]*len(ct))
	# sys.exit(0)
	# # print brute[88]
	# print 8*(len(binarystring))
	#print chr(xor_char)*len(binarystring)
	return fixed_xor(binarystring, chr(xor_char)*len(binarystring))
	# Check weather whole strings is printiable 

	# Check character frequencies

def character_frequency(binarystring):

	# First create some dictionaries with default values
	freqs = collections.defaultdict(int)
	freqs_percent = collections.defaultdict(int)
	freqs_english = collections.defaultdict(int)

	# Specify all ascii characters including non printables
	all_ascii = []
	all_ascii.append(k for k in xrange(255))

	# Populate freqs_english dict with frequency of english text
	freqs_english = {'a': 8.167, 'b':1.492, 'c':2.782, 'd':4.253, 'e':12.702, 'f':2.228, 'g':2.015, 'h':6.094, 'i':6.966, \
	'j':0.153, 'k':0.772, 'l':4.025, 'm':2.406, 'n':6.749, 'o':7.507, 'p':1.929, 'q':0.095, 'r':5.987, 's':6.327, 't':9.056, \
	'u':2.758, 'v':0.978, 'w':2.360, 'x':0.150, 'y':1.974, 'z':0.074}

	# Populate the freqs dict with frequency count of binary string
	for c in binarystring:
		d = c.lower()
	 	freqs[d] += 1


	# Cacaulte percentages of frequency count for binary string
	for i in string.printable:
		freqs_percent[i] = 100 * float(freqs[i])/float(len(binarystring))

	# debug print
	#print freqs
	# print '\n'
	# print freqs_percent

	# Caculate the frequency score by comparing binary string with English letter freqency
	# Store an int that contains overall frequency_score.  Lower number is higher probablity we found a match
	frequency_score = 0
	diffkeys = [k for k in freqs_english if freqs_english[k] != freqs_percent[k]]# and freqs_percent[k] > 0]
	for k in diffkeys:
  		#print k, ':', freqs_english[k], '->', freqs_percent[k]
  		frequency_score += abs((freqs_english[k] - freqs_percent[k]))
		#freq = n/5 if n else 999
	# divide ount by overall legnth of string gives you frequency %

	print frequency_score
	return frequency_score



#print single_xor
all_ascii = []
some_test = []
all_ascii.append(k for k in xrange(255))
for i in range(1,255):
	xored = single_xor(binascii.a2b_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), i)
	#print str(xored)
	# RETURN MIN OF LOWEST VALUE
	some_test.append(i, xored)
	print character_frequency(xored), '->', chr(i)
'''
3. Single-character XOR Cipher

The hex encoded string:

      1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

      plaintext
      ^
      xxxxxxxxxx


... has been XOR'd against a single character. Find the key, decrypt
the message.

Write code to do this for you. How? Devise some method for "scoring" a
piece of English plaintext. (Character frequency is a good metric.)
Evaluate each output and choose the one with the best score.

Tune your algorithm until this works.

// ------------------------------------------------------------

4. Detect single-character XOR

One of the 60-character strings at:

  https://gist.github.com/3132713

has been encrypted by single-character XOR. Find it. (Your code from
#3 should help.)
'''