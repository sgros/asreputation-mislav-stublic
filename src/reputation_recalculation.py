import sys
import csv
#import subprocess
import os
#import operator
from ConfigParser import ConfigParser

REPUTATIONCONFFILE = 'reputation_system.conf'

def rw1(rw1_old, rw1, traffic, alpha):
	#print rw1_old, rw1
	rep = rw1_old * alpha + rw1 * (1 - alpha)
	#rep2 = rep / traffic
	#print timeStampOld, rep
	return rep
	
def rw2(rw2v, rw1v, traffic, alpha):
	#print rw1v, rw2v, traffic, timeStampOld
	if traffic == 0:
		temp = 0
	else:
		temp = (1 - alpha) * (rw1v/traffic)
	rep = alpha * rw2v + temp
	#print rep
	return rep

def rw3(rw3v, rw1v, traffic, errorCount, alpha):
	if errorCount == 0 and traffic == 0:
		temp = 0
	else:
		temp = (1 - alpha) * (rw1v / (errorCount + traffic))
	rep = rw3v * alpha + temp
	#print rep
	return rep

def rw4(rw4v, rw1v, errorCount, alpha):
	if errorCount == 0:
		temp = 0
	else:
		temp = (1 - alpha) * (rw1v / errorCount)
	rep = rw4v * alpha + temp
	#print rep
	return rep
	
def rw5(rw5v, rw1v, traffic, errorCount, alpha):
	if traffic == 0:
		temp = 0
	else:
		temp = (1 - alpha) * (rw1v * errorCount / traffic)
	rep = rw5v * alpha + temp
	#print rep
	return rep	

def main(argv):
	allFileList = os.listdir('./' + argv[0] + '/')
	ASFileList = []
	for i in allFileList:
		if i.find('rep') == -1:
			ASFileList.append(i)
	#for i in asFileList:
	#print ASFileList
	
	reputationConf = ConfigParser()
	reputationConf.read(REPUTATIONCONFFILE)
	alpha = reputationConf.getfloat('parameters','alpha')
	
	#try:
	#	os.mkdir('./new_rep')
	#except OSError:
	#	print "directory new_rep already exists"
	try:
		os.mkdir('./new_rep_' + argv[0])
	except OSError:
		print "directory new_rep already exists"
	
	for ASFile in ASFileList:
	
		csv_reader = csv.reader(open('./' + argv[0] + '/' + ASFile, 'r'), delimiter=',')
		csv_writer = csv.writer(open('./new_rep_' + argv[0] + '/' + ASFile.rstrip('trc.csv') + 'rep.csv', 'w'))
		
		timeStampOld = 0
		timeStampNew = 0
		timeBool = True
		timePrint = False
		first = True
		option = ''
		end_rw1 = False
		rw1v = 0.0
		rw1v_old = 0.0
		rw2v = 0.0
		#rw2_old = 0
		rw3v = 0.0
		#rw3_old = 0
		rw4v = 0.0
		#rw4_old = 0
		rw5v = 0.0
		#rw5_old = 0
		traffic = 0
		errorCount = 0
	
		for row in csv_reader:
			try:
				if timeBool and not first:
					timeStampOld = timeStampNew
					timeBool = False
					timePrint = True
			
				first = False
				#print row		
				timeStampNew = float(row[0])
				if end_rw1 or timePrint:
					rw1v_old = rw1(rw1v_old, rw1v, traffic, alpha)
					rw2v = rw2(rw2v, rw1v, traffic, alpha)
					#rw2 = 0
					rw3v = rw3(rw3v, rw1v, traffic, errorCount, alpha)
					#rw3 = 0
					rw4v = rw4(rw4v, rw1v, errorCount, alpha)
					#rw4 = 0
					rw5v = rw5(rw5v, rw1v, traffic, errorCount, alpha)
					#rw5 = 0
					csv_writer.writerow((timeStampOld, round(rw1v_old, 3), 
								round(rw2v, 3), round(rw3v, 3), 
								round(rw4v, 3), round(rw5v, 3)))
					traffic = 0
					errorCount = 0
					rw1v = 0
					#print timeStampOld, rw1 * 0.5
					timeBool = True
					timePrint = False
					end_rw1 = False
				#timeBool = True
				#end_rw1 = True
			
				#print timeStamp	
			except ValueError:		
				if row[0].find('client side') != -1:
					option = 'client'
					end_rw1 = True	
					#print row
				elif row[0].find('server side') != -1:
					option = 'server'
					end_rw1 = True
					#end_rw1 = True
					#print row
				else:
					for j in row:
						error = j.split('=')
						rw1v += reputationConf.getfloat(option, error[0]) * float(error[1])
						if error[0] == 'all_traffic':
							traffic += int(error[1])
							#print traffic
						elif error[0] != 'dnsbl':
							errorCount += int(error[1])
							#print errorCount
					#print errorCount
						
	
		if end_rw1 or (timeStampNew != timeStampOld):
			rw1v_old = rw1(rw1v_old, rw1v, traffic, alpha)
			rw2v = rw2(rw2v, rw1v, traffic, alpha)
			rw3v = rw3(rw3v, rw1v, traffic, errorCount, alpha)
			rw4v = rw4(rw4v, rw1v, errorCount, alpha)
			rw5v = rw5(rw5v, rw1v, traffic, errorCount, alpha)
			csv_writer.writerow((timeStampNew, round(rw1v_old, 3), round(rw2v, 3), round(rw3v, 3), round(rw4v, 3), round(rw5v, 3)))
			#print timeStampOld, rw1 * 0.5
			#end_rw1 = False	
	
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
