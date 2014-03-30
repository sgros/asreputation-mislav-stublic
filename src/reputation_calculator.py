import sys
import socket
import pickle
import csv
import os
import time
import logging
from datetime import datetime, timedelta
from ConfigParser import ConfigParser
from IPy import IP
from Queue import Empty

REPUTATIONCONFFILE = 'reputation_system.conf'
WHOIS_SERVER='whois.cymru.com'
WHOIS_PORT=43
LOGFMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

class ReputationCalculator:
	"""Class calculates reputation based on a prior AS reputation knowledge and
	new error data provided by analysis class, and basic error class
	"""
	def __init__(self, reputationQueue, stopThread):
		# set up thread communication queues
		self.reputationQueue = reputationQueue
		self.stopThread = stopThread
		
		# read configuration file
		self.reputationConf = ConfigParser()
		self.reputationConf.read(REPUTATIONCONFFILE)
		
		# local variables
		self.ASclientErrorCounter = {}
		self.ASserverErrorCounter = {}
		self.knownAS = []
		self.current_R = {}
		self.unknownIP = []
		self.alpha = self.reputationConf.getfloat('parameters','alpha')
		
		# local constants
		self.RFC1918 = [IP('172.16.0.0/12'), 
						IP('192.168.0.0/16'), 
						IP('10.0.0.0/8')]
		self.multicast = IP('224.0.0.0/4')

		# determine if rw function's directories exist
		try:
			os.mkdir('./rw1')
		except OSError:
			print "Directory rw1 already exists"
		
		for Rt_method in self.reputationConf.options('functions'):
			try:
				os.mkdir('./' + Rt_method)
			except OSError:
				print "Directory " + Rt_method + " already exists"
		
		# construct a IP to AS database
		try:
			ipDatabaseFile = open('./data/' + 
							self.reputationConf.get('basic','IP_AS_file'), 'rb')
			self.ipDatabase = pickle.load(ipDatabaseFile)
		except IOError, UnboundLocalError:
			print ("IP to AS file \'" + 
							self.reputationConf.get('basic','IP_AS_file') + 
							"\' not found in /data directory or data error!")
			self.ipDatabase = {}
		
		# setup a local DNS server IP if it exists
		self.localDNSset = self.reputationConf.getboolean('basic','local_DNS')
		
		if self.localDNSset:
			self.localDNSip = self.reputationConf.get('basic','local_DNS_IP')
		else:
			self.localDNSip = ''
		
		# read my_networks for networks excluded from reputation calculation
		self.myNetworksSet = self.reputationConf.getboolean('basic', 'my_networks')
		self.myNetworks = []
		
		if self.myNetworksSet:
			try:
				networks_file = open('./data/' + 
						self.reputationConf.get('basic','my_networks_file'), 'r')
				for line in networks_file:
					self.myNetworks.append(IP(line))
			except IOError:
				print ("My network file \'" + 
						self.reputationConf.get('basic','my_networks_file') + 
						"\' does not exist!")
		else:
			print "No skiped networks!"
		
		# setup logging
		logHandler = logging.FileHandler('reputation_calculator.log')
		logHandler.setLevel(logging.DEBUG)
		self.log = logging.getLogger('reputation_calculator')
		self.log.addHandler(logHandler)
		self.log.info('Started at %s' % time.asctime())
		
		# start main reputation calculation function
		self.__mainReputationCalculationProcess()
		
	
	def __mainReputationCalculationProcess(self):
		"""Main reputation calculation loop. Gets new error packets, calls sort
		errors by AS function, set up new reputation recalculation time, call 
		reputation recalculation, call save IP data
		"""
		nextCalculationTime = datetime.now()
		firstTime = True
		
		# main program loop
		while True:
			# get new error packet. If queue is empty see if program should exit
			try:			
				errorPacket = self.reputationQueue.get(True, 8)
			except Empty:
				if self.stopThread.is_set():
					self.__saveIPdata()
					break
				else:
					continue
			
			# if new reputation calculation reached start new calculation
			if (datetime.fromtimestamp(errorPacket['timestamp']) > 
				nextCalculationTime):
				
				# start new reputation calculation
				print 'Recalculating reputation...'
				self.__newReputationCalculation(nextCalculationTime)
				print 'Done.'
			
				# save collected IP to AS data
				print 'Saving IP to AS data...'
				self.__saveIPdata()
				print 'Done.'
			
				# before we continue collecting errors we need to reinitialize
				# AS error counters for the next hour
				del self.ASclientErrorCounter
				del self.ASserverErrorCounter
				self.ASclientErrorCounter = {}
				self.ASserverErrorCounter = {}
				firstTime = True
			
			# set new reputation calculation time
			if firstTime:
				timeBool = True
				nextCalculationTime = datetime.fromtimestamp(errorPacket['timestamp'])
				
				nextCalculationTime = nextCalculationTime.replace(hour=0, 
																minute=0, 
																second=0, 
																microsecond=0)
			
				for i in range(0, 24, 24/self.reputationConf.getint('parameters','time_divisor')):
					if ((nextCalculationTime + timedelta(hours=i)) > 
						datetime.fromtimestamp(errorPacket['timestamp'])):
						nextCalculationTime += timedelta(hours=i)
						timeBool = False
						print 'Next reputation calculation at:'
						print nextCalculationTime
						break
				if timeBool:
					nextCalculationTime += timedelta(days=1)
					print "Next reputation calculation at:"
					print nextCalculationTime
				firstTime = False			
			
			# collect analysis data and sort by AS
			self.__sortTrafficByAS(errorPacket)
	
	def __selectSide(self, errorPacket):
		"""Function determines whether source or destination IP should be
		excluded from reputation calculation, and calls find AS by IP function
		"""
		clientAS = 0
		serverAS = 0
		
		# test client side for IP address exceptions in DNS question
		if ((self.localDNSset and self.localDNSip == errorPacket['src_ip']) or 
			(self.myNetworksSet and self.__myNetwork(errorPacket['src_ip']))):
			clientAS = -1
		elif ((not self.__validASAddress(errorPacket['src_ip'])) or 
			(self.__isMulticast(errorPacket['src_ip']))):
			clientAS = self.__findNeighbourAS(errorPacket['src_ip'])				
		else:
			clientAS = self.__findASbyAddress(errorPacket['src_ip'])
							
		# test server side for IP address exceptions in DNS question
		if ((self.localDNSset and errorPacket['dst_ip'] == self.localDNSip) or 
			(self.myNetworksSet and self.__myNetwork(errorPacket['dst_ip']))):
			serverAS = -1
		elif ((not self.__validASAddress(errorPacket['dst_ip'])) or 
			(self.__isMulticast(errorPacket['dst_ip']))):
			serverAS = -1
		else:
			serverAS = self.__findASbyAddress(errorPacket['dst_ip'])
		
		return clientAS, serverAS
			
	def __sortTrafficByAS(self, errorPacket):
		"""Creates error counter for every AS and sorts errors by AS
		"""
		clientAS = 0
		serverAS = 0
		
		# determine client and server side, and find AS responsible
		if errorPacket['question'] == '0L':
			clientAS, serverAS = self.__selectSide(errorPacket)
		elif errorPacket['question'] == '1L':
			serverAS, clientAS = self.__selectSide(errorPacket)
		
		if clientAS != -1:			
			# create error counter dictionaries for found AS
			if clientAS not in self.ASclientErrorCounter:
				self.ASclientErrorCounter[clientAS] = dict((x, 0) for x in self.reputationConf.options('client'))
				
				# initialize a new found AS reputation to zero (neutral)
				if clientAS not in self.knownAS:
					self.current_R[clientAS] = [0] * len(self.reputationConf.options('functions'))
		
			# increment error counter for the current AS and error
			self.ASclientErrorCounter[clientAS][errorPacket['error_filter']] += 1
		
			# put new AS in known AS list
			if clientAS not in self.knownAS:
				self.knownAS.append(clientAS)
		
		# the same for the server side AS
		if serverAS != -1:
			if serverAS not in self.ASserverErrorCounter:
				self.ASserverErrorCounter[serverAS] = dict((x, 0) for x in self.reputationConf.options('server'))
				# initialize a new found AS reputation to zero (neutral)
				if serverAS not in self.knownAS:
					self.current_R[serverAS] = [0] * len(self.reputationConf.options('functions'))		
			
			self.ASserverErrorCounter[serverAS][errorPacket['error_filter']] += 1
		
			if serverAS not in self.knownAS:
				self.knownAS.append(serverAS)
		
		del serverAS
		del clientAS

	def __newReputationCalculation(self, nextCalculationTime):
		"""Calls selected weight functions and overall reputation calculator.
		Also call store reputation function.
		"""
		for currentAS in self.knownAS:
			Rw = []
			
			Rw.append(self.rw1(currentAS))
			# calculate new Rw functions values for every known AS
			for Rw_method in self.reputationConf.options('functions'):
				if Rw_method == 'rw_all':
					continue
				if (self.reputationConf.getboolean('functions', Rw_method) or 
					self.reputationConf.getboolean('functions', 'Rw_all')):					
					Rw.append(getattr(self, Rw_method)(currentAS, Rw[0]))
				else:
					Rw.append(0)
			
			# calculate new reputation
			tempR = self.__calculate_Rn(currentAS, Rw)
			del self.current_R[currentAS]
			self.current_R[currentAS] = tempR
			del Rw
			
			# store new reputation
			self.__storeNewReputation(currentAS, nextCalculationTime)
	
	def __findASbyAddress(self, ip):
		"""For a given IP address determine AS it belongs to.
		Parts written by Tomislav Friscic
		"""

		if ip in self.ipDatabase:
			return self.ipDatabase[ip]
		
		if ip in self.unknownIP:
			self.log.error('IP to AS unsuccessful, IP: %s ' % ip)
			return -1

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((WHOIS_SERVER, WHOIS_PORT))
		sock.send('begin\n' + ip + '\nend\n')
		response = sock.recv(4096)
		sock.close()
		whoisResponse = response.replace('\n', '|').split('|')
		
		# whois server might not know the answer
		try:
			self.ipDatabase[ip] = int(whoisResponse[1])
		except ValueError:
			if ip not in self.unknownIP:
				self.unknownIP.append(ip)
			print ip, "unknown AS"
			self.log.error('IP to AS unsuccessful, IP: %s ' % ip)
			
			del sock
			del response
			del whoisResponse
			
			return -1
		
		return self.ipDatabase[ip]
	
	
	def rw1(self, currentAS):
		"""Rw1 summation function -> Rw1 = b0*r0 + b1*r1 + ... + bn*rn
		rx - number of occurences of specific error
		bx - weight (severity) of specific error represented by conf file error
		filters values
		"""
		rClient = 0
		rServer = 0
		if currentAS in self.ASclientErrorCounter:
			# weight factor product summation for current AS in role of a client
			for errorFilter, errorCount in self.ASclientErrorCounter[currentAS].iteritems():
				if (errorFilter != 'all_traffic' or 
					self.reputationConf.getboolean(
										'analyses','all_traffic_penalties')):
					rClient += (errorCount * 
							int(self.reputationConf.get('client', errorFilter)))
		
		if currentAS in self.ASserverErrorCounter:
			# weight factor product summation for current AS in role of a server
			for errorFilter, errorCount in self.ASserverErrorCounter[currentAS].iteritems():
				if (errorFilter != 'all_traffic' or 
					self.reputationConf.getboolean(
										'analyses','all_traffic_penalties')):
					rServer += (errorCount * 
							int(self.reputationConf.get('server', errorFilter)))
		
		Rw1 = rClient + rServer
		
		return Rw1

	def rw2(self, currentAS, Rw):
		"""Rw2 weight function.
		Rw2 = Rw1/(oveall AS traffic)
		"""
		allTrafficCount = 0
		if currentAS in self.ASclientErrorCounter:
			allTrafficCount += self.ASclientErrorCounter[currentAS]['all_traffic']
		if currentAS in self.ASserverErrorCounter:
			allTrafficCount += self.ASserverErrorCounter[currentAS]['all_traffic']

		if allTrafficCount == 0:
			return 0
		
		return float(Rw)/allTrafficCount
	
	def rw3(self, currentAS, Rw, all_error=True):
		"""Rw3 weight function.
		Rw3 = Rw1/(oveall AS traffic + number of errors)
		"""
		errorCount = self.__count_errors(currentAS, all_error)
		if errorCount == 0:
			return 0
		
		return float(Rw)/errorCount	
	
	def rw4(self, currentAS, Rw):
		"""Rw4 weight function.
		Rw4 = Rw1 / (number of errors)
		"""
		return self.rw3(currentAS, Rw, all_error=False)
	
	def rw5(self, currentAS, Rw):
		"""Rw5 weight function.
		Rw5 = (number of errors)*Rw1/(overall AS traffic)
		"""
		return self.__count_errors(currentAS, False) * self.rw2(currentAS, Rw)
	
	def __calculate_Rn(self, currentAS, Rw):
		"""For every weight function call reputation function.
		Limit results to five decimals
		"""
		new_Rn = []
		
		for RwIndex, RwValue in enumerate(Rw):
			new_Rn.append(self.__final_Rn(currentAS, RwIndex, RwValue))
		
		# limit reputation to five decimals
		for i, j in enumerate(new_Rn):
			if (abs(j) < 0.00001) and (abs(j) > 0):
				new_Rn[i] = 0.0
		
		return new_Rn
	
	def __final_Rn(self, currentAS, RwIndex, RwValue):
		"""Final reputation calculation.
		reputation function -> R_new = alpha*R_old + (1 - alpha)*Rw
		alpha, <0,1> -> decay factor
		"""
		return (self.alpha*self.current_R[currentAS][RwIndex]) + ((1 - self.alpha)*RwValue)
		
	def __count_errors(self, currentAS, all_error):
		"""Count errors for every AS in both client and server role. Used in
		Rw3, Rw4 and Rw5 weight functions 
		"""
		errorCount = 0
		if currentAS in self.ASclientErrorCounter:
			for errorFilter in self.ASclientErrorCounter[currentAS]:
				if ((errorFilter != 'dnsbl') and 
					(all_error or (errorFilter != 'all_traffic'))):
					errorCount += self.ASclientErrorCounter[currentAS][errorFilter]
		
		if currentAS in self.ASserverErrorCounter:
			for errorFilter in self.ASserverErrorCounter[currentAS]:
				if ((errorFilter != 'dnsbl') and 
					(all_error or (errorFilter != 'all_traffic'))):
					errorCount += self.ASserverErrorCounter[currentAS][errorFilter]
		return errorCount
	
	def __storeNewReputation(self, currentAS, nextCalculationTime):
		"""Sets up new reptuation data to be stored int two csv files. First is
		reputation file and second is error trace. 
		"""
		tempL = list(self.current_R[currentAS])
		tempTime = time.mktime(nextCalculationTime.timetuple())
		
		for i, j in enumerate(tempL):
			tempL[i] = round(tempL[i], 3)
		
		tempL.insert(0, tempTime)
		
		
		clientTempL = []
		serverTempL = []
		
		if currentAS in self.ASclientErrorCounter:
			for errorFilter, errorCount in self.ASclientErrorCounter[currentAS].iteritems():
				if errorCount != 0:
					clientTempL.append(errorFilter + '=' + str(errorCount))
					
		if currentAS in self.ASserverErrorCounter:
			for errorFilter, errorCount in self.ASserverErrorCounter[currentAS].iteritems():
				if errorCount != 0:
					serverTempL.append(errorFilter + '=' + str(errorCount))
		
		if self.reputationConf.getboolean('functions','Rw_all'):
			self.__reputationWriter('rw_all', currentAS, tempL, tempTime, 
									clientTempL, serverTempL)
		else:
			self.__reputationWriter('rw1', currentAS, [tempL[0], tempL[1]], 
									tempTime, clientTempL, serverTempL)
			
			for Rw_index, Rw_method in enumerate(self.reputationConf.options('functions')):
				if (self.reputationConf.getboolean('functions',Rw_method) and 
					(Rw_method != 'rw_all')):
					self.__reputationWriter(Rw_method, currentAS, [tempL[0], 
											tempL[Rw_index + 2]], tempTime, 
											clientTempL, serverTempL)

		del tempL
		del clientTempL
		del serverTempL
		del tempTime
		
	def __reputationWriter(self, Rw_method, currentAS, tempL, tempTime, clientTempL, serverTempL):
		"""Stores reputation and error trace date for a given AS
		"""
		writer = csv.writer(open('./' + Rw_method + '/AS' + str(currentAS) + 'rep.csv', 'a'))
		writer.writerow(tempL)
		
		del writer
		
		writer = csv.writer(open('./' + Rw_method + '/AS' + str(currentAS) + 'trc.csv', 'a'))
		writer.writerow([tempTime])
		if clientTempL != []:
			writer.writerow(['client side'])
			writer.writerow(clientTempL)
		if serverTempL != []:
			writer.writerow(['server side'])
			writer.writerow(serverTempL)
		
		del writer
	
	def __validASAddress(self, ipaddress):
		"""Determines whether a given IP address is not a RFC1918 address.
		"""
		for localNet in self.RFC1918:
			if ipaddress in localNet:
				return False

		return True
		
	def __myNetwork(self, ip):
		"""Determines whether an IP is a part od networks ommited from
		reputation calculation.
		"""
		for myNet in self.myNetworks:
			if ip in myNet:
				return True
		
		return False
		
	def __isMulticast(self, ip):
		"""Determines if an IP address is a multicast address so it must be 
		ignored.
		"""
		if ip in self.multicast:
			return True
		
		return False

	def __findNeighbourAS(self, ip):
		"""Implement neighbour AS search for a given IP
		"""
		return -1

	def __saveIPdata(self):
		"""Saves IP to AS data in two files, one regular and the other backup
		"""
		ipDatabaseFile = open('./data/ip_to_as_backup', 'w')
		pickle.dump(self.ipDatabase, ipDatabaseFile)
		ipDatabaseFile.close()
		
		ipDatabaseFile = open('./data/ip_to_as', 'w')
		pickle.dump(self.ipDatabase, ipDatabaseFile)
		ipDatabaseFile.close()
