#!/usr/bin/python

import os
import subprocess
import re
import sys


###################################################################################################
#runs the CITRIC script
def runscript(ip, fn):
   test=subprocess.check_output(['./CITRIC', ip, fn], shell=False)

###################################################################################################
#change initialize conffile from template
def initconf(fn):
   try:
     os.remove(fn);
   except:
     print 'no old conf deleted'
   os.system('cp '+fn+'.template '+fn)

###################################################################################################
#change parameter in file
def addconf(par, value, fn):
   os.system('cp '+fn+' '+fn+'.temp')
   with open(fn+'.temp', 'r') as infile:
      with open(fn, 'w') as outfile:
         for i, line in enumerate(infile):
            match = re.search(par+'\s', line)
            if match:
               outfile.write('SETVAL '+par+' '+value+'\n')
            else:
               outfile.write(line)
   os.remove(fn+'.temp')

###################################################################################################
#extract parameter from file
def extractpar(index, searchstring, fn):
   with open(fn, 'r') as infile:
      for i, line in enumerate(infile):
         #match = re.search(searchstring+'\s+(\d+)', line)
         match = re.search(searchstring+'\s+([0-9]*\.?[0-9]*)', line)



         if match:
            return match.group(1)
      return -1


###################################################################################################
###################################################################################################
#main script

#STEP 1 PROCESS ARGS
Name=sys.argv[1]
print '\nProcessing: '+Name
os.chdir('./')

with open(Name+'.run', 'r') as infile:
  for i, line in enumerate(infile):
    match = re.search('(\S+)\s+(\S+)', line)
    if match:
      if match.group(1)=='Path':
        Path=match.group(2)
      elif match.group(1)=='IP':
        IP=match.group(2)
      elif match.group(1)=='Parameter':
        Parameter=match.group(2)
      elif match.group(1)=='RangeLow':
        RangeLow=int(match.group(2))
      elif match.group(1)=='RangeHigh':
        RangeHigh=int(match.group(2))
      elif match.group(1)=='RangeStep':
        RangeStep=int(match.group(2))

#STEP 2 INIT
#Path='test'
#IP='145.52.126.46'
#Parameter='DELTA_T_USER'
#RangeLow=0
#RangeHigh=2000001
#RangeStep=100000

print Path
print IP
print Parameter
print RangeLow
print RangeHigh
print RangeStep

initconf('CITRIC.conf')
try:
  os.remove(Name+'.cvs')
except:
  print 'no old cvs deleted'

analysisfile=open(Name+'.cvs','a')

analysisfile.write('Name, Run, Trees, User, DNS, DNSDel, URL, URLDel, SURL, SURLDel, Unknown, Unknowndns, Unknownother, Nameless, BareIP, OpenWindow\n')

#STEP 3 RANGING AND SETTING PARAMS
for i in range(RangeLow, RangeHigh, RangeStep):
   addconf(Parameter, str(i), 'CITRIC.conf')
   print "RUN WITH ", i

   #STEP 4 RUNNING THE SCRIPT
   for filename in os.listdir(Path):
      if filename.endswith('.pcap'):
         match = re.search('(.+).pcap', filename)
         if match:
           barename = match.group(1)
           runscript(IP, Path+'/'+filename)

           #STEP 5 EXTRACTING PARAMETERS
           unknown = extractpar(i, 'Total unknown cause FLowCount:', 'results/'+barename+'.stats')
           unknowndns = extractpar(i, 'Unknown used DNS FLowCount:', 'results/'+barename+'.stats')
           unknownother = extractpar(i, 'Unknown non-DNS Flowcount:', 'results/'+barename+'.stats')
           nameless = extractpar(i, 'Total nameless FLowCount:', 'results/'+barename+'.stats')
           bareip = extractpar(i, 'Netto bare IP FLowCount:', 'results/'+barename+'.stats')

           trees = extractpar(i, 'Total created TreeCount:', 'results/'+barename+'.stats')
           user = extractpar(i, 'User caused FlowCount:', 'results/'+barename+'.stats')
           openwindow = extractpar(i, 'Aggregated open window time:', 'results/'+barename+'.stats')

           dns = extractpar(i, 'DNS caused FlowCount:', 'results/'+barename+'.stats')
           latedns = extractpar(i, 'Late DNS caused FlowCount:', 'results/'+barename+'.stats')
           url = extractpar(i, 'URL caused FlowCount:', 'results/'+barename+'.stats')
           lateurl = extractpar(i, 'Late URL caused FlowCount:', 'results/'+barename+'.stats')
           surl = extractpar(i, 'P-URL caused FlowCount:', 'results/'+barename+'.stats')
           latesurl = extractpar(i, 'Late P-URL caused FlowCount:', 'results/'+barename+'.stats')

           #STEP 6 RESULTS TO FILE
           analysisfile.write(barename+', '+str(i)+', '+str(trees)+', '+str(user)+', '+str(dns)+', '+str(latedns)+', '+str(url)+', '+str(lateurl)+', '+str(surl)+', '+str(latesurl)+', '+str(unknown)+', '+str(unknowndns)+', '+str(unknownother)+', '+str(nameless)+', '+str(bareip)+', '+str(openwindow)+'\n')

#STEP 7 CLOSE
analysisfile.close()

