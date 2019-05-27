#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# 	Ultra Security Team

#  Telegram: @ultrasecurity
#  Website : https://ultrasec.org

"""
copyrigth(c) 2018 ultra security team
author: siruidops
:D 
"""

from color import *
import hashlib
import sys

def run(hash,password):
	print
	print green+" [*] Decrypting (%s%s%s)[%sSHA256%s]%s"%(yellow,hash,green,yellow,green,end)
	passwds = password.split('\n')
	for passwd in passwds:
		passwd = passwd.strip()
		key = passwd
		t = hashlib.new("sha256")
		t.update(passwd)
		if hash == t.hexdigest():
			print green+" [*] Your hash is '%s%s%s'%s"%(yellow,key,green,end)
			sys.exit()
		else:
			print red+" [-] Invalid: '%s%s%s'%s"%(yellow,key,red,end)