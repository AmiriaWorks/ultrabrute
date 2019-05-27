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

import base64, sys
from color import *

def run(hash):
	print
	print green+" [*] Decrypting (%s%s%s)[%sBase64%s]%s"%(yellow,hash,green,yellow,green,end)
	try:
		key = base64.b64decode(hash)
	except:
		print red+" [-] Hash is invalid"+end
		sys.exit()
	print green+" [*] Your hash is '%s%s%s'%s"%(yellow,key,green,end)
	print
