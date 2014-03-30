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
			tempL[tempIndex] = round(float(rep)/(rowIndex + 1), 3)
			
		for asIndex, repValue in enumerate(tempL):
			as_dict_list[asIndex][i[2:].rstrip('rep.csv')] = repValue
	
	for elemIndex, elem in enumerate(as_dict_list):
		tempS[elemIndex] = sorted(as_dict_list[elemIndex].iteritems(), key=operator.itemgetter(1))
	
	writer = csv.writer(open(argv[0] + '_worst20.csv', 'w'))
	
	for worst20 in range(20):
		writer.writerow(((tempS[0][worst20][0], str(tempS[0][worst20][1])),
				 (tempS[1][worst20][0], str(tempS[1][worst20][1])),
				 (tempS[2][worst20][0], str(tempS[2][worst20][1])), 
				 (tempS[3][worst20][0], str(tempS[3][worst20][1])), 
				 (tempS[4][worst20][0], str(tempS[4][worst20][1]))))
	
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
