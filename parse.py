import csv
import re

#Open file containing source functions and create dictionary
with open('source.csv', mode='r') as infile: 
	reader = csv.reader(infile)
	with open('source_new.csv', mode='w') as outfile: 
		writer = csv.writer(outfile)
		source = {rows[0]:rows[1] for rows in reader}

#Open file containing sink functions and create dictionary
with open('sink.csv', mode='r') as infile: 
	reader = csv.reader(infile)
	with open('sink_new.csv', mode='w') as outfile: 
		writer = csv.writer(outfile)
		sink = {rows[0]:rows[1] for rows in reader}

#Create report file
file1 = open("report.txt", "w")

#Create taint list and data tuple
taint = list()
data = tuple()
flag = 0
#filename = 'com.example.thespecial.tryapplication.MainActivity.shimple'
filename = 'aa.shimple'

#Regular expression to catch variables assigned values
pattern = re.compile('(\$.._*.*) = ')
pattern
with open(filename, 'r') as f:
	lines = f.readlines()

for line in lines: 
	m = re.search(pattern, line)
	#if pattern is found
	if m:
		#Assign destvar the variable name
		destvar = m.group(1)
		spl = line.split()
		#Search for any source functions in the line
		for key in source:
			regex = re.compile('(%s.*)'%key)
			for string in spl:
				n = re.search(regex, string)
				if n:
					print key
					data = (destvar, 1, source[key], 'Original')
					taint.append(data)
					flag = 1
					break
				else: 
					if spl.index(string) < 2:
						data = (destvar, 0, 'N/A', 'N/A')
					else: 
						for tup in taint:
							#print tup
							reg = re.compile('(\%s)'%tup[0])
							x = re.search(reg, string)
							if x:
								if tup[1] == 0:
									data = (destvar, 0, 'N/A', 'N/A')
								else:
									data = (destvar, 1, tup[2], tup[0])
									break
					
		if flag == 0:
			taint.append(data)
		else:
			flag = 0	
		print spl
		print '\n'

	#If pattern not found, search for sink function
	else:
		spl2 = line.split()
		for key in sink:
			regex2 = re.compile('(.*%s.*)'%key)
			for string in spl2:
				n = re.search(regex2, string)
				#If sink function located
				if n:
					print key 
					print spl2
					print '\n'
					for string in spl2:
						for tup in taint:
								reg = re.compile('(.*\%s.*)'%tup[0])
								x = re.search(reg, string)
								#If variable used in sink function
								if x:
									print "Variable Leaked: %s", tup[0]
									#Variable not sensitive
									if tup[1] == 0:
										print "Variable tainted: No"
										print '\n'
									#Variable is sensitive
									else:
										print "Variable tainted: Yes"
										print "Information leaked: %s", tup[2]
										print '\n'
										file1.write(line + '\n')
										file1.write('Sink function: ' + repr(key) + '\n')
										file1.write('Variable Leaked: ' + repr(tup[0]) + '\n')
										file1.write('Information Leaked: ' + repr(tup[2]) + '\n')
										file1.write('Tainting Variable: ' + repr(tup[3]) + '\n\n\n')
print taint, '\n'
		
#Print taint table to report
file1.write('Taint table: \n')
file1.write('Var\t\tTaint\tInfo\t\tPropagation\n')
for tup in taint: 
	reg = re.compile('(.*_.*)')
	x = re.search(reg, tup[0])
	if x:
		file1.write(repr(tup[0]) + '\t' + repr(tup[1]) + '\t\t' + repr(tup[2]) + '\t\t' + repr(tup[3]) + '\n') 
	else:
		file1.write(repr(tup[0]) + '\t\t' + repr(tup[1]) + '\t\t' + repr(tup[2]) + '\t\t' + repr(tup[3]) + '\n') 
