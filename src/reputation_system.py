#!/usr/bin/env python

import sys
import sniff_sensor
import traffic_analysis
import reputation_calculator
import threading
import Queue
from ConfigParser import ConfigParser
from scapy.all import *

REPUTATIONCONFFILE = 'reputation_system.conf'

def reputationCalculatorStarter(reputationQueue, stopThread):
	"""Starts reputation calculator
	"""
	
	calculatorObject = reputation_calculator.ReputationCalculator(
													reputationQueue, stopThread)
	print "Calculator finished!"

def analysisThreadStarter(trafficQueue, reputationQueue, stopThread):
	"""Starts traffic analyses.
	"""
	analysis = traffic_analysis.AnalysisProcess(
									  trafficQueue, reputationQueue, stopThread)
	print "Analysis finished!"

def sensorStarter(trafficQueue, reputationQueue, stopThread):
	"""Start scapy sniff function for a chosen pcap file
	"""
	
	# read conf file for pcap information
	reputationConf = ConfigParser()
	reputationConf.read(REPUTATIONCONFFILE)
		
	pcap_file = reputationConf.get('basic','pcap_file')
	
	trafficFlow = sniff_sensor.DNSFlowClient(trafficQueue,
											 reputationQueue,
											 stopThread)
		
	sniff(prn=trafficFlow.monitor_callback, offline=pcap_file,
		  filter=trafficFlow.pcapexpr, store=0)

def main(argv):
	reputationConf = ConfigParser()
	reputationConf.read(REPUTATIONCONFFILE)
	
	try:
		open(reputationConf.get('basic', 'pcap_file'), 'r')
	except IOError:
		raise IOError('DNS pcap file does not exist in program directory!')
	
	
	if (24 % reputationConf.getint('parameters','time_divisor')) != 0:
		raise ValueError('Wrong time divisor! Should be 1, 2, 3, 4, 6, 8, 12, or 24.')
	
	stopThread = threading.Event()
	trafficQueue = Queue.Queue()
	reputationQueue = Queue.Queue()
	
	# start main AS reputation calculation thread
	reputationCalculatorThread = threading.Thread(
											target=reputationCalculatorStarter, 
											args=(reputationQueue, stopThread))
	reputationCalculatorThread.start()
	
	# start analysis thread, includes all analyses except for basic errors
	trafficAnalysisThread = threading.Thread(target=analysisThreadStarter,
								args=(trafficQueue,reputationQueue,stopThread))
	trafficAnalysisThread.start()

	try:
		sensorStarter(trafficQueue, reputationQueue, stopThread)
	except KeyboardInterrupt:
		print 'Forced quit in scapy sniff unsuccessful! Shutting down program!'
		
	stopThread.set()
	
	print "Finishing program. Waiting for other threads!" 
	reputationCalculatorThread.join()
	trafficAnalysisThread.join()
	print "End!"
	
if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
