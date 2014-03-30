import sys
import csv
import os
import operator

def main(argv):
	as_dict_list = [{}, {}, {}, {}, {}]
	tempS = [[],[],[],[],[]]
	asFileList = []
	allFileList = os.listdir('./new_rep_' + argv[0])
	for i in allFileList:
		if i.find('trc') == -1:
			asFileList.append(i)
	tempL = [0, 0, 0, 0, 0]
	for i in asFileList:
		csv_reader = csv.reader(open('./new_rep_' + argv[0] + '/' + i, 'r'), delimiter=',')
		for rowIndex, row in enumerate(csv_reader):
			for colIndex, column in enumerate(row):
				if colIndex != 0:
					tempL[colIndex - 1] += float(column)
		
		for tempIndex, rep in enumerate(tempL):
			tempL[tempIndex] = round(float(rep)/13, 3) #(rowIndex + 1), 3)
			
		for asIndex, repValue in enumerate(tempL):
			as_dict_list[asIndex][i[2:].rstrip('rep.csv')] = repValue
	
	for elemIndex, elem in enumerate(as_dict_list):
		tempS[elemIndex] = sorted(as_dict_list[elemIndex].iteritems(), key=operator.itemgetter(1))
	
	
	najgori = []
	
	for iIndex, i in enumerate(tempS[0]):
		for jIndex, j in enumerate(tempS[1]):
			if i[0] == j[0]:
				druga = jIndex + 1
				break
		for kIndex, k in enumerate(tempS[4]):
			if i[0] == k[0]:
				peta = kIndex + 1
				break
		najgori.append(((iIndex + 1) + (3 * jIndex) + kIndex, i[0]))
	
	najgori.sort()
	for i in range(20):
		print i
		print najgori[i]

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
