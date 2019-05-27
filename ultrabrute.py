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
import os
import getpass
import hashlib
import time

from core.main import Main
from core.color import *

import modules.wordp as wordp
import modules.joom as joom
import modules.drup as drup
import modules.oth as oth

import modules.m5 as m5
import modules.sh1 as sh1
import modules.sh224 as sh224
import modules.sh256 as sh25
import modules.sh384 as sh384
import modules.sh512 as sh512
import modules.m4 as m4
import modules.ripemd as ripemd
import modules.m5_raw as m5_raw
import modules.base as base

import modules.gm as gm
import modules.ig as ig

site = ''

class Ultrabrute:
	def __init__(self):
		Ultrabrute.main(self)
		site = ''
	def main(self):
		os.system("clear")
		Main()
		print """

	%smulti cracker by %sultrasec %steam
	%shttp://ultrasec.org
	%shttp://t.me/ultrasecurity

	%s1) %sWebSite    %s2) %sAccounts
	%s3) %sHashs      %s4) %sExit
		"""%(pur,green,
		pur,tur,
		tur,pur,
		blue,pur,
		blue,pur,
		blue,pur,
		blue)
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/# "%(green,end,pur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '1':
			Ultrabrute.website(self)
		elif re == '2':
			Ultrabrute.accounts(self)
		elif re == '3':
			Ultrabrute.hash(self)
		elif re == '4':
			sys.exit(red+'Bye :D ...'+end)
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute()
	def accounts(self):
		os.system('clear')
		Main()
		print
		print green+"	Please select the account type"+end
		print
		print "	%s1) %sGmail       %s2) %sInstagram"%(pur,blue,pur,blue)
		print "                 %s3) %sBack%s"%(pur,blue,end)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s# "%(green,end,pur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '1':
			Ultrabrute.gmail(self)
		elif re == '2':
			Ultrabrute.insta(self)
		elif re == '3':
			Ultrabrute()
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.accounts(self)
	def insta(self):
		os.system('clear')
		Main()
		print
		print green+"	Please select the Attack type"+end
		print
		print "	%s1) %sCombo file         %s2) %sUser - Passwd file"%(pur,blue,pur,blue)
		print "	                %s3) %sBack"%(pur,blue)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sinstagram%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '1': #combofile
			os.system('clear')
			Main()
			print
			print green+"	Please enter your combo file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sinstagram%s/%scombo%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				words = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'File not found: Bye :D ...'+end)
			user = []
			passwd = []
			for i in words:
				p = i.split(':')
				user.append(p[0])
				passwd.append(p[-1])
			user = '\n'.join(user)
			passwd = '\n'.join(passwd)
			ig.run(
			comboAttack=True,
			usernames=user,
			passwords=passwd)
		elif re == '2': #userpassfile
			os.system('clear')
			Main()
			print
			print green+"	Please enter username"+end
			print
			try:
				user = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sinstagram%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sinstagram%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				passwds = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			passwd = []
			for i in passwds:
				passwd.append(i.strip())
			passwd = '\n'.join(passwd)
			ig.run(
			usernames=user,
			passwords=passwd)
		elif re == '3yxyoccjclhclhxutci': #userfilepass
			os.system('clear')
			Main()
			print
			print green+"	Please enter username file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sinstagram%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				users = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password "+end
			print
			try:
				passwd = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sinstagram%s/%suserfile-passwd%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			user = []
			for i in users:
				user.append(i.strip())
			user = '\n'.join(passwd)
			ig.run(
			usernames=user,
			passwords=passwd)
		elif re == '3': #back
			Ultrabrute.accounts(self)
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.insta(self)
		
	def gmail(self):
		os.system('clear')
		Main()
		print
		print green+"	Please select the Attack type"+end
		print
		print "	%s1) %sCombo file         %s2) %sEmail - Passwd file"%(pur,blue,pur,blue)
		print "	                %s3) %sBack"%(pur,blue)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sgmail%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '1': #combofile
			os.system('clear')
			Main()
			print
			print green+"	Please enter your combo file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sgmail%s/%scombo%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				words = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'File not found: Bye :D ...'+end)
			user = []
			passwd = []
			for i in words:
				p = i.split(':')
				user.append(p[0])
				passwd.append(p[-1])
			user = '\n'.join(user)
			passwd = '\n'.join(passwd)
			gm.run(
			comboAttack=True,
			usernames=user,
			passwords=passwd)
		elif re == '2': #userpassfile
			os.system('clear')
			Main()
			print
			print green+"	Please enter username"+end
			print
			try:
				user = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sgmail%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sgmail%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				passwds = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			passwd = []
			for i in passwds:
				passwd.append(i.strip())
			passwd = '\n'.join(passwd)
			gm.run(
			usernames=user,
			passwords=passwd)
		elif re == '3bxdbbdbbsndnndhndhdidd': #userfilepass
			os.system('clear')
			Main()
			print
			print green+"	Please enter username file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sgmail%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				users = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password "+end
			print
			try:
				passwd = raw_input("%sultrabrute%s@%sultrasec%s:/%saccounts%s/%sgmail%s/%suserfile-passwd%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			user = []
			for i in users:
				user.append(i.strip())
			user = '\n'.join(passwd)
			gm.run(
			usernames=user,
			passwords=passwd)
		elif re == '3': #back
			Ultrabrute.accounts(self)
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.gmail(self)

	def hash(self):
		os.system('clear')
		Main()
		print
		print green+"	Please select the hash type"+end
		print
		print "	%s1) %sMD5         %s2) %sSHA1"%(pur,blue,pur,blue)
		print "	%s3) %sSHA224      %s4) %sSHA256"%(pur,blue,pur,blue)
		print "	%s5) %sSHA384      %s6) %sSHA512"%(pur,blue,pur,blue)
		print "	%s7) %sMD5-rev     %s8) %sripemd160"%(pur,blue,pur,blue)
		print "	%s9) %sMD4         %s10)%sBase64"%(pur,blue,pur,blue)
		print "               %s11) %sBack"%(pur,blue) 
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s# "%(green,end,pur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '1': #MD5
			Ultrabrute.md5(self)
		elif re == '2': #SHA1
			Ultrabrute.sha1(self)
		elif re == '3': #SHA224
			Ultrabrute.sha224(self)
		elif re == '4': #SHA256
			Ultrabrute.sha256(self)
		elif re == '5': #SHA384
			Ultrabrute.sha384(self)
		elif re == '6': #SHA512
			Ultrabrute.sha512(self)
		elif re == '7': #md5-rev
			Ultrabrute.md5_rev(self)
		elif re == '8': #ripemd160
			Ultrabrute.riprmd160(self)
		elif re == '9': #MD4
			Ultrabrute.md4(self)
		elif re == '10': #Base64
			Ultrabrute.base64(self)
		elif re == '11': #Back
			Ultrabrute()
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.hash(self)
	def md5(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%smd5%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system('clear')
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%smd5%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		m5.run(hash=myhash,
		password=passwd)
	def sha1(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha1%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha1%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		sh1.run(hash=myhash,
		password=passwd)
	def sha224(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha224%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha224%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		sh224.run(hash=myhash,
		password=passwd)
	def sha256(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha256%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha256%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		sh256.run(hash=myhash,
		password=passwd)
	def sha384(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha384%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha384%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		sh384.run(hash=myhash,
		password=passwd)
	def sha512(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha384%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%ssha384%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		sh384.run(hash=myhash,
		password=passwd)
	def md5_raw(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%smd5-rev%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%smd5-rev%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		m5_raw.run(hash=myhash,
		password=passwd)
	def ripemd160(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%sripemd160%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%sripemd160%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		ripemd.run(hash=myhash,
		password=passwd)
	def md4(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%smd4%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system("clear")
		Main()
		print
		print green+"	Please enter your file"+end
		print
		try:
			passwdfile = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%smd4%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		try:
			o = open(passwdfile)
			words = o.readlines()
			o.close()
		except IOError:
			sys.exit(red+'File not found: Bye :D ...'+end)
		passwd = '\n'.join(words)
		m4.run(hash=myhash,
		password=passwd)
	def base64(self):
		os.system('clear')
		Main()
		print
		print green+"	Please enter your hash"+end
		print
		try:
			global myhash
			myhash = raw_input("%sultrabrute%s@%sultrasec%s:/%shash%s/%sBase64%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		base.run(hash=myhash.strip())
	def website(self):
		os.system('clear')
		Main()
		print
		print green+"	Please select the site type"+end
		print
		print "	%s1) %sWordpress         %s2) %sJoomla"%(pur,blue,pur,blue)
		print "	%s3) %sDrupal            %s4) %sOther"%(pur,blue,pur,blue)
		print "                    %s5) %sBack"%(pur,blue) 
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s# "%(green,end,pur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '1': #Wordpress
			Ultrabrute.wordpress(self)
		elif re == '2': #Joomla
			Ultrabrute.joomla(self)
		elif re == '3': #Drupal
			Ultrabrute.drupal(self)
		elif re == '4': #Other
			Ultrabrute.other(self)
		elif re == '5': #Back
			Ultrabrute()
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.website(self)

	def drupal(self): #Drupal
		def site():
			os.system('clear')
			Main()
			print
			print green+"	Please enter admin page location\n\tExmaple: http://site.com/admin"+end
			print
			try:
				global sitel
				sitel = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sdrupal%s# "%(green,end,pur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			
		site()
		os.system('clear')
		Main()
		print
		print green+"	Please select the Attack type"+end
		print
		print "	%s1) %sUser-Passfile         %s2) %sBack"%(pur,blue,pur,blue)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sdrupal%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == 'gcjcivivi1': #combofile
			os.system('clear')
			Main()
			print
			print green+"	Please enter your combo file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sdrupal%s/%scombo%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				words = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'File not found: Bye :D ...'+end)
			user = []
			passwd = []
			for i in words:
				p = i.split(':')
				user.append(p[0])
				passwd.append(p[-1])
			user = '\n'.join(user)
			passwd = '\n'.join(passwd)
			drup.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == '1': #userpassfile
			os.system('clear')
			Main()
			print
			print green+"	Please enter username"+end
			print
			try:
				user = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sdrupal%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sdrupal%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				passwds = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			passwd = []
			for i in passwds:
				passwd.append(i.strip())
			passwd = '\n'.join(passwd)
			drup.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == 'jendnndnd3': #userfilepass
			os.system('clear')
			Main()
			print
			print green+"	Please enter username file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sdrupal%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				users = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password "+end
			print
			try:
				passwd = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sdrupal%s/%suserfile-passwd%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			user = []
			for i in users:
				user.append(i.strip())
			user = '\n'.join(passwd)
			drup.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == '2': #back
			Ultrabrute.website(self)
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.drupal(self)


	def other(self): ## Other -------------
		def sites():
			os.system('clear')
			Main()
			print
			print green+"	Please enter admin page location\n\tExmaple: http://site.com/administrator"+end
			print
			try:
				global sitel
				sitel = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s# "%(green,end,pur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			
		sites()
		os.system('clear')
		Main()
		print
		print green+"	Please enter user name field"+end
		print
		try:
			userfield = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system('clear')
		Main()
		print
		print green+"	Please enter pass name field"+end
		print
		try:
			passfield = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		os.system('clear')
		Main()
		print
		print green+"	Please enter text error"+end
		print
		try:
			errorTxt = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		
		os.system('clear')
		Main()
		print
		print green+"	Please select the Attack type"+end
		print
		print "	%s1) %sCombo file         %s2) %sUser - Passwd file"%(pur,blue,pur,blue)
		print "	               %s3) %sBack"%(pur,blue)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '1': #combofile
			os.system('clear')
			Main()
			print
			print green+"	Please enter your combo file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s/%scombo%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				words = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'File not found: Bye :D ...'+end)
			user = []
			passwd = []
			for i in words:
				p = i.split(':')
				user.append(p[0])
				passwd.append(p[-1])
			user = '\n'.join(user)
			passwd = '\n'.join(passwd)
			oth.run(url=sitel,
			comboAttack=True,
			usersfield=userfield,
			passsfield=passfield,
			usernames=user,
			passwords=passwd,
			error=errorTxt)
		elif re == '2': #userpassfile
			os.system('clear')
			Main()
			print
			print green+"	Please enter username"+end
			print
			try:
				user = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				passwds = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			passwd = []
			for i in passwds:
				passwd.append(i.strip())
			passwd = '\n'.join(passwd)
			oth.run(url=sitel,
			usersfield=userfield,
			passsfield=passfield,
			usernames=user,
			passwords=passwd,
			error=errorTxt)
		elif re == '3bdbsbhsjdhd': #userfilepass
			os.system('clear')
			Main()
			print
			print green+"	Please enter username file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				users = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password "+end
			print
			try:
				passwd = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sother%s/%suserfile-passwd%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			user = []
			for i in users:
				user.append(i.strip())
			user = '\n'.join(passwd)
			oth.run(url=sitel,
			usersfield=userfield,
			passsfield=passfield,
			usernames=user,
			passwords=passwd,
			error=errorTxt)
		elif re == '3': #back
			Ultrabrute.website(self)
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.other(self)

	def joomla(self): #Joomla
		def sites():
			os.system('clear')
			Main()
			print
			print green+"	Please enter admin page location\n\tExmaple: http://site.com/administrator"+end
			print
			try:
				global sitel
				sitel = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sjoomla%s# "%(green,end,pur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			
		sites()
		os.system('clear')
		Main()
		print
		print green+"	Please select the Attack type"+end
		print
		print "	%s1) %sUser-PassFile         %s2) %sBack"%(pur,blue,pur,blue)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sjoomla%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '938388': #combofile
			os.system('clear')
			Main()
			print
			print green+"	Please enter your combo file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sjoomla%s/%scombo%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				words = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'File not found: Bye :D ...'+end)
			user = []
			passwd = []
			for i in words:
				p = i.split(':')
				user.append(p[0])
				passwd.append(p[-1])
			user = '\n'.join(user)
			passwd = '\n'.join(passwd)
			joom.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == '1': #userpassfile
			os.system('clear')
			Main()
			print
			print green+"	Please enter username"+end
			print
			try:
				user = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sjoomla%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sjoomla%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				passwds = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			passwd = []
			for i in passwds:
				passwd.append(i.strip())
			passwd = '\n'.join(passwd)
			joom.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == '02728273855353': #userfilepass
			os.system('clear')
			Main()
			print
			print green+"	Please enter username file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sjoomla%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				users = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password "+end
			print
			try:
				passwd = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%sjoomla%s/%suserfile-passwd%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			user = []
			for i in users:
				user.append(i.strip())
			user = '\n'.join(passwd)
			joom.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == '2': #back
			Ultrabrute.website(self)
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.joomla(self)


	def wordpress(self):
		def sites():
			os.system('clear')
			Main()
			print
			print green+"	Please enter admin page location\n\tExmaple: http://site.com/wp-login.php"+end
			print
			try:
				global sitel
				sitel = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%swordpress%s# "%(green,end,pur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
		sites()
		os.system('clear')
		Main()
		print
		print green+"	Please select the Attack type"+end
		print
		print "	%s1) %sUser-Passfile         %s2) %sBack"%(pur,blue,pur,blue)
		print
		try:
			re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%swordpress%s# "%(green,end,pur,end,tur,end,tur,end))
		except KeyboardInterrupt:
			sys.exit(red+'Bye :D ...'+end)
		if re == '3i38i3i3je1': #combofile
			os.system('clear')
			Main()
			print
			print green+"	Please enter your combo file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%swordpress%s/%scombo%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				words = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'File not found: Bye :D ...'+end)
			user = []
			passwd = []
			for i in words:
				p = i.split(':')
				user.append(p[0])
				passwd.append(p[-1])
			user = '\n'.join(user)
			passwd = '\n'.join(passwd)
			wordp.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == '1': #userpassfile
			os.system('clear')
			Main()
			print
			print green+"	Please enter username"+end
			print
			try:
				user = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%swordpress%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%swordpress%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				passwds = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			passwd = []
			for i in passwds:
				passwd.append(i.strip())
			passwd = '\n'.join(passwd)
			wordp.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == 'jjejejjejejd3': #userfilepass
			os.system('clear')
			Main()
			print
			print green+"	Please enter username file"+end
			print
			try:
				re = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%swordpress%s/%suser-passfile%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			try:
				o = open(re)
				users = o.readlines()
				o.close()
			except IOError:
				sys.exit(red+'PassFile not found: Bye :D ...'+end)
			os.system('clear')
			Main()
			print
			print green+"	Please enter password "+end
			print
			try:
				passwd = raw_input("%sultrabrute%s@%sultrasec%s:/%sWebSite%s/%swordpress%s/%suserfile-passwd%s# "%(green,end,pur,end,tur,end,tur,end,tur,end))
			except KeyboardInterrupt:
				sys.exit(red+'Bye :D ...'+end)
			user = []
			for i in users:
				user.append(i.strip())
			user = '\n'.join(passwd)
			wordp.run(url=sitel,
			usernames=user,
			passwords=passwd)
		elif re == '2': #back
			Ultrabrute.website(self)
		else:
			print red+" Command not find (%s) [%srestarting in 5sec%s]%s"%(re,green,red,end)
			time.sleep(5)
			os.system('clear')
			Ultrabrute.wordpress(self)



def init():
	try:
		passLicense = getpass.getpass()
		hashLicense = hashlib.md5(hashlib.sha512(passLicense).hexdigest()).hexdigest()
		license = "1f81a6e754dfd298fa0be7ea125ef340"
		if hashLicense == license:
			w = open('../.ultralicense',"w")
			one = "a53012ccd61af8e733ad74d5f48ab203"
			two = "1f81a6e754dfd298fa0be7ea125ef340"
			thr = "3bcd980c90a7a995d78ae1584a434bd2"
			fou = "96082a0bed56e42c1d92b1f447fe7cfa"
			buf = "%s\n%s\n%s\n%s"%(one,two,thr,fou)
			w.write(buf)
			w.close()
			print green+" [*] password accepted ! (reload in 5s)"+end
			time.sleep(5)
			Ultrabrute()
		else:
			sys.exit(red+"Password not accepted: Bye :D ..."+end)
	except KeyboardInterrupt:
		sys.exit(red+"Bye :D ..."+end)



if __name__ == '__main__':
	try:
		o = open('../.ultralicense')
		words = o.readlines()
		o.close()
		if words[0].strip() == "a53012ccd61af8e733ad74d5f48ab203":
			if words[1].strip() == "1f81a6e754dfd298fa0be7ea125ef340":
				Ultrabrute()
			else:
				init()
		else:
			init()
	except IOError:
		init()


