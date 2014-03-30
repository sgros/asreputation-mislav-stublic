import time
import logging
from Queue import Queue, Empty
from ConfigParser import ConfigParser

REPUTATIONCONFFILE = 'reputation_system.conf'
ALLOWED_RCODE = ["ok",
				"format-error",
				"server-failure",
				"name-error",
				"not-implemented",
				"refused"]
LOGFMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

class AnalysisProcess:
	"""Class implements negative answer penalties, DNSBL search, positive
	aspects and TTL penalization
	"""
	def __init__(self, trafficQueue, reputationQueue, stopThread):
		self.trafficQueue = trafficQueue
		self.reputationQueue = reputationQueue
		self.stopThread = stopThread
		
		# read conf file for basic info and penalties
		self.reputationConf = ConfigParser()
		self.reputationConf.read(REPUTATIONCONFFILE)
		
		# read the DNSBL list
		try:
			self.dnsbl = []
			f = open('./data/' + 
					self.reputationConf.get('basic','dnsbl_file'), 'r')
			self.dnsbl = f.readlines()
			f.close()
		except IOError:
			print ("DNSBL file \'" + 
					self.reputationConf.get('basic','dnsbl_file') + 
					"\' does not exist in /data directory")
	
		# create DNSBL list
		for i, j in zip(self.dnsbl, range(len(self.dnsbl))):
			self.dnsbl[j] = i.rstrip('\n')
		
		self.dnsbl = list(set(self.dnsbl))
		
		# setup logging
		logHandler = logging.FileHandler('traffic_analysis.log')
		logHandler.setLevel(logging.DEBUG)
		self.log = logging.getLogger('traffic_analysis')
		self.log.addHandler(logHandler)
		self.log.info('Started at %s' % time.asctime())

		# start main analysis function
		self.__mainAnalysisFlow()
		
	def __negativeAnswer(self, packet):
		"""Determine if packet is negative answer and send it to reputation
		calculator
		"""
		if packet['DNS']['qr'] == '1L' and packet['DNS']['rcode'] != 'ok':
			if packet['DNS']['rcode'] == 'name-error':
				self.__nameErrorAnalysis(packet)
			else:
				# ignore BIND 15L RCODE error
				if packet['DNS']['rcode'] not in ALLOWED_RCODE:
					self.log.error('Wrong RCODE found, received at: %s, %s ' % 
								(time.ctime(packet['rcvtime']), packet))
					return
				else:
					self.__sendErrorPacket(packet, packet['DNS']['rcode'])
		
	def __positiveAspectsAnalysis(self, packet):
		"""Search for positive aspects, mainly DNSSEC, not implemented due to
		Scapy version not supporting DNSSEC
		"""
		pass

	def __allTrafficPenalties(self, packet):
		"""Penalize all traffic. Also used for counting traffic for each AS
		"""
		self.__sendErrorPacket(packet, 'all_traffic')
		if self.reputationConf.getboolean('analyses','penalize_ttl'):
			self.__penalizeTTL(packet)
	
	def __mainAnalysisFlow(self):
		"""Main analysis loop. Call every selected analysis
		"""
		while True:
			try:
				packet = self.trafficQueue.get(True, 8)
			
				# start negative answer analysis, includes DNSBL search
				if self.reputationConf.getboolean('analyses',
												'negative_answer_analysis'):
					self.__negativeAnswer(packet)
			
				# search for positive aspects, should mainly be DNSSEC
				if self.reputationConf.getboolean('analyses',
												'positive_aspects_analysis'):
					self.__positiveAspectsAnalysis(packet)
			
				# penalize all traffic, includes TTL penalization
				self.__allTrafficPenalties(packet)
			except Empty:
				if self.stopThread.is_set():
					break
	
	def __nameErrorAnalysis(self, packet):
		"""Function used to determine if a name error is in fact a DNSBL
		respone in which case it should be rewarded
		"""
		if not isinstance(packet['DNS']['qd']['DNS Question Record'], list):
			packet['DNS']['qd']['DNS Question Record'] = [
									packet['DNS']['qd']['DNS Question Record']]
			
		qname = packet['DNS']['qd']['DNS Question Record'][0]['qname']
		for i in self.dnsbl:
			if qname.find(i) != -1:
				self.__sendErrorPacket(packet, 'dnsbl')
				return
		# ignore BIND 15L RCODE error
		if packet['DNS']['rcode'] not in ALLOWED_RCODE:
			self.log.error('Wrong RCODE found, received at: %s, %s ' % 
								(time.ctime(packet['rcvtime']), packet))
			return
		else:
			self.__sendErrorPacket(packet, packet['DNS']['rcode'])
	
	def __penalizeTTL(self, packet):
		"""Used to penlize short TTL values. It only uses first answer TTL
		for comparison.
		"""
		if 'an' in packet['DNS']:
			# ignore erroneous DNS packets found during testing
			if packet['DNS']['an'] == '':
				self.log.error('Erroneous DNS packet received at: %s, %s ' % 
								(time.ctime(packet['rcvtime']), packet))
				return
			
			if not isinstance(packet['DNS']['an']['DNS Resource Record'], list):
				packet['DNS']['an']['DNS Resource Record'] = [
									packet['DNS']['an']['DNS Resource Record']]
			if (long(packet['DNS']['an']['DNS Resource Record'][0]['ttl']) <= 
				long(self.reputationConf.get('parameters', 'ttl_low'))):
				self.__sendErrorPacket(packet, 'ttl_low')
			elif (long(packet['DNS']['an']['DNS Resource Record'][0]['ttl']) > 
			      long(self.reputationConf.get('parameters', 'ttl_low')) 
			      and long(packet['DNS']['an']['DNS Resource Record'][0]['ttl']) <=
			      long(self.reputationConf.get('parameters', 'ttl_medium'))):
				self.__sendErrorPacket(packet, 'ttl_medium')
			else:
				self.__sendErrorPacket(packet, 'ttl_high')
	
	def __sendErrorPacket(self, packet, error_filter):
		"""Function constructs error packet based on packet and error filter
		information. It then sends it to the reputation calculator.
		"""
		try:
			errorPacket = {'src_ip':packet['IP']['src'], 
							'dst_ip':packet['IP']['dst'], 
							'question':packet['DNS']['qr'], 
							'error_filter':error_filter, 
							'timestamp': packet['rcvtime']}
		except KeyError:
			self.log.error('IPv6 packet ignored, received at: %s, %s ' % 
								(time.ctime(packet['rcvtime']), packet))
			return
		self.reputationQueue.put(errorPacket)
