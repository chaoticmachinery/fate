#!/usr/bin/env python3 

#https://github.com/omerbenamram/evtx
from evtx import PyEvtxParser
import os.path
import argparse
import io
import logging
import json
import jsbeautifier
from re import search
import os, sys, getopt
from pathlib import Path
import re
#Config ini
from configparser import ConfigParser 

version = '0.1'
coldelimiter = '|'

def retrieve_nested_value(mapping, key_of_interest):
    mappings = [mapping]
    while mappings:
        mapping = mappings.pop()
        try:
            items = mapping.items()
        except AttributeError:
            # we didn't store a mapping earlier on so just skip that value
            continue

        for key, value in items:
            if key == key_of_interest:
                yield value
            else:
                # type of the value will be checked in the next loop
                mappings.append(value)

def printjson(dic):
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        res=jsbeautifier.beautify(json.dumps(dic), opts)
        #print(res)
        return(res)
       
    
def parseproblem(dic, outfile):
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        res=jsbeautifier.beautify(json.dumps(dic), opts)
        print(res)
        outfile.write("Parsing Problem\n")
        tmphold = res + "\n"
        outfile.write(tmphold)
        
        
        
eventidtxt = { 
    #Sources:
    # https://nsfocusglobal.com/Attack-and-Defense-Around-PowerShell-Event-Logging
    # https://www.blackhat.com/docs/us-14/materials/us-14-Kazanciyan-Investigating-Powershell-Attacks.pdf
    # https://www.powershellmagazine.com/2014/07/16/investigating-powershell-attacks/
    # https://resources.infosecinstitute.com/topic/powershell-remoting-artifacts-part-1/
    #
    #Windows PowerShell.evtx
    '400'  : 'Start of any local or remote PowerShell activity (Local PowerShell Execution)',
    '403'  : 'End of any local or remote PowerShell activity (Local PowerShell Execution)',
    '600'  : 'Indicates a provider is starting a PowerShell activity',
    #Microsoft-Windows-Powersell%4Operational.evtx (Dst Host)
    '4103' : 'Command invocationa and parameter bindings',
    '4104' : 'Scriptblock text (Local PowerShell Execution); Note may be a continuation from a previous 4104 log.',
    '4100' : 'Script failed to run (Local PowerShell Execution)',
    '40961': 'Start time of the PowerShell session  (Local PowerShell Execution)',
	#System.evtx  (Dst Host)
	'7030' : '',
	'7040' : 'Recorded when PowerShell remoting is enabled',
    '7045' : '',
    #Microsoft-Windows-WinRM/Operational.evtx
    '6'    : 'Remote handling activity is started on the client system, including the destination address to which the system is connected. (Remoting)',
    '81'   : 'Processing Client request for operation',
    '82'   : 'Request handling',
    '134'  : 'Request handling',
    '142'  : 'If WinRM is disabled on the remote server, this event is recorded when the client attempts to initiate a remote shell connection. (Remoting)',
    '169'  : 'Authentication prior to PowerShell remoting on a accessed system (Remoting)',
    #Security
    '4688' : 'Indicates the execution of PowerShell console or interpreter',
    #AppLocker
    '8005' : '[script_path] was allowed to run',
    '8006' : '[script_path] was allowed to run but would have been prevented from running if the AppLocker policy were enforced',
}



def parseevtx(infile,outdir,coldelimiter,jsonfile):  
    outfilenametmp = os.path.basename(infile) + ".csv"
    if jsonfile == 1:
       jsonoutfilenametmp = os.path.basename(infile) + ".json"
    drive,outfiledir = os.path.splitdrive(os.path.dirname(infile))
    
    #Make Dir
    harddir = outdir +os.sep+ outfiledir
    outfilename = harddir +os.sep+ outfilenametmp        
    os.makedirs(harddir, exist_ok=True)
    print(f'CVS Out Info : {outfilename}') 
    if jsonfile == 1:
       jsonoutfilename = harddir +os.sep+ jsonoutfilenametmp
       print(f'JSON Out Info: {jsonoutfilename}') 
       jsonoutfile = open(jsonoutfilename,'w')    
    
    #           #1          #2            #3             #4            #5        #6            #7                                      #8         #9                #10       #11
    header = "'EventID'|'ComputerName'|'TimeCreated'|'Security SID'|'UserID'|'Address'|'Script/IP:Port'|'Payload/Path/Correlation Activity ID'|'Event'|'Channel (EVTX Log)'|'SRC File'\n"
    #create file
    outfile = open(outfilename,'w')
    outfile.write("Please note that depending on the CSV deliminater used, the fields may not line up.\n") 
    outfile.write(header)
      
    parser = PyEvtxParser(infile)
    print(f'Working on: {infile}')    
    for record in parser.records_json():
        subrec = json.loads(record["data"])
        
        lineout = ""
        try:
           eventid = subrec['Event']['System']['EventID']          #['#text']
        except:
           eventid = subrec['Event']['System']['EventID']['#text'] 
        channel = subrec['Event']['System']['Channel']
        computer = subrec['Event']['System']['Computer']
        systemtime = subrec['Event']['System']['TimeCreated']['#attributes']['SystemTime']
        
        #print(subrec['Event']['UserData']['EventXML'].keys())
        if jsonfile == 1:
           if channel == "Windows PowerShell" or channel == "Microsoft-Windows-WinRM/Operational" or channel == "Microsoft-Windows-PowerShell/Operational" or channel == "Security" or channel == "System":
              jsonoutfile.write(printjson(subrec))
              jsonoutfile.write("\n")
           
        #print(f'EID: {eventid}')
        #--------------------------------------------------------------------------------------------------------------------------------          
        #Windows PowerShell.evtx
        if eventid == 400 or eventid == 403 or eventid == 600:
           if channel == "Windows PowerShell":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + ""+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter  #6
                 tmpstr = ''
                 tmpstr = tmpstr.join(subrec['Event']['EventData']['Data']['#text'])
                 lineout = lineout + "'" + tmpstr + "'"+coldelimiter   #7
                 lineout = lineout + ""+coldelimiter #8
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter  #10
                 lineout = lineout + "'" + infile + "'"  #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)
        #--------------------------------------------------------------------------------------------------------------------------------   
        #Microsoft-Windows-WinRM/Operational.evtx
        if eventid == 6:
           if channel == "Microsoft-Windows-WinRM/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter  #6
                 lineout = lineout + "'Connecting remotely to: " + subrec['Event']['EventData']['connection'] + "'"+coldelimiter   #7
                 try:
                    lineout = lineout + "'" + subrec['Event']['System']['Correlation']['#attributes']['ActivityID'] + "'"+coldelimiter  #8
                 except: 
                    lineout = lineout + "''"+coldelimiter 
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter   #10
                 lineout = lineout + "'" + infile + "'"  #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)
        if eventid == 81:
           if channel == "Microsoft-Windows-WinRM/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter  #6
                 lineout = lineout + "'Operation Name: " + subrec['Event']['EventData']['operationName'] + "'"+coldelimiter   #7
                 try:
                    lineout = lineout + "'" + subrec['Event']['System']['Correlation']['#attributes']['ActivityID'] + "'"+coldelimiter  #8
                 except: 
                    lineout = lineout + "''"+coldelimiter 
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter   #10
                 lineout = lineout + "'" + infile + "'"  #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)
        if eventid == 82:
           if channel == "Microsoft-Windows-WinRM/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter  #6
                 lineout = lineout + "'Operation: " + subrec['Event']['EventData']['operation'] + " -- Resource URI: " + subrec['Event']['EventData']['resourceURI'] + "'" + coldelimiter   #7
                 try:
                    lineout = lineout + "'" + subrec['Event']['System']['Correlation']['#attributes']['ActivityID'] + "'"+coldelimiter  #8
                 except: 
                    lineout = lineout + "''"+coldelimiter 
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter   #10
                 lineout = lineout + "'" + infile + "'"  #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)          
        if eventid == 134:
           if channel == "Microsoft-Windows-WinRM/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter  #6
                 lineout = lineout + "'Operation: " + subrec['Event']['EventData']['operationName'] + "'" + coldelimiter   #7
                 try:
                    lineout = lineout + "'" + subrec['Event']['System']['Correlation']['#attributes']['ActivityID'] + "'"+coldelimiter  #8
                 except: 
                    lineout = lineout + "''"+coldelimiter 
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter   #10
                 lineout = lineout + "'" + infile + "'"  #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)                  
        # Need an example log related to powershell; now it prints out all 142 events
        if eventid == 142:
           if channel == "Microsoft-Windows-WinRM/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter  #6
                 lineout = lineout + "'OperatinName: " + subrec['Event']['EventData']['operationName'] + " -- Error Code :'" + str(subrec['Event']['EventData']['errorCode']) +coldelimiter   #7
                 try:
                    lineout = lineout + "'" + subrec['Event']['System']['Correlation']['#attributes']['ActivityID'] + "'"+coldelimiter  #8
                 except: 
                    lineout = lineout + "''"+coldelimiter 
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter   #10
                 lineout = lineout + "'" + infile + "'"  #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)                
        if eventid == 169:
           if channel == "Microsoft-Windows-WinRM/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + "'" + subrec['Event']['EventData']['username'] + "'"+coldelimiter  
                 lineout = lineout + ""+coldelimiter  #6
                 lineout = lineout + "'Authentication Mechanism: " + subrec['Event']['EventData']['authenticationMechanism'] + "'"+coldelimiter   #7
                 try:
                    lineout = lineout + "'" + subrec['Event']['System']['Correlation']['#attributes']['ActivityID'] + "'"+coldelimiter  #8
                 except: 
                    lineout = lineout + "''"+coldelimiter 
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter   #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter   #10
                 lineout = lineout + "'" + infile + "'"  #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)
        #--------------------------------------------------------------------------------------------------------------------------------     
        #Microsoft-Windows-PowerShell/Operational.evtx 
        if eventid == 4100:
           if channel == "Microsoft-Windows-PowerShell/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter  #6
                 tmpstr = ''
                 tmpstr = tmpstr.join(subrec['Event']['EventData']['ContextInfo'])
                 lineout = lineout + "'" + tmpstr + "'"+coldelimiter  #7
                 lineout = lineout + "'" + subrec['Event']['EventData']['Payload'] + "'"+coldelimiter   #8
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter   #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter   #10
                 lineout = lineout + "'" + infile + "'"   #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)      
        if eventid == 4103:
           if channel == "Microsoft-Windows-PowerShell/Operational":
              try:
                 #printjson(subrec) ScriptBlockText
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter #6
                 tmpstr = ''
                 tmpstr = tmpstr.join(subrec['Event']['EventData']['ContextInfo'])
                 lineout = lineout + "'" + tmpstr + "'"+coldelimiter  #7
                 lineout = lineout + "'" + subrec['Event']['EventData']['Path'] + "'"+coldelimiter   #8
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter  #10
                 lineout = lineout + "'" + infile + "'"   #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)
        if eventid == 4104:
           if channel == "Microsoft-Windows-PowerShell/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter #6
                 tmpstr = ''
                 tmpstr = tmpstr.join(subrec['Event']['EventData']['ScriptBlockText'])
                 lineout = lineout + "'" + tmpstr + "'"+coldelimiter  #7
                 lineout = lineout + "'" + subrec['Event']['EventData']['Path'] + "'"+coldelimiter   #8
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter  #10
                 lineout = lineout + "'" + infile + "'"   #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)
        if eventid == 40961:
           if channel == "Microsoft-Windows-PowerShell/Operational":
              try:
                 #printjson(subrec) 
                 address = ''
                 lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                 lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                 lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                 lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                 lineout = lineout + ""+coldelimiter  #5
                 lineout = lineout + ""+coldelimiter #6
                 lineout = lineout + ""+coldelimiter #7
                 lineout = lineout + ""+coldelimiter #8
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                 lineout = lineout + "'" + channel + "'"+coldelimiter  #10
                 lineout = lineout + "'" + infile + "'"   #11
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)                 
        #--------------------------------------------------------------------------------------------------------------------------------     
        #Security
        if eventid == 4688:
           if channel == "Security":
              try:
                 if re.search('powershell',subrec['Event']['EventData']['NewProcessName'],re.IGNORECASE):
                    #printjson(subrec) 
                    address = ''
                    lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                    lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                    lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                    lineout = lineout + "'" + subrec['Event']['EventData']['SubjectDomainName'] + "\\" + subrec['Event']['EventData']['SubjectUserName'] + " ("+ subrec['Event']['EventData']['SubjectUserSid'] +")'"+coldelimiter  #4
                    lineout = lineout + ""+coldelimiter  #5
                    lineout = lineout + ""+coldelimiter #6
                    try:
                       tmpstr = subrec['Event']['EventData']['CommandLine']
                       try:
                          tmpppn = subrec['Event']['EventData']['ParentProcessName']
                       except:
                          tmpppn = ''
                       if tmpstr: 
                             lineout = lineout + "'" + tmpppn + " -> " + subrec['Event']['EventData']['CommandLine'] + "'"+coldelimiter  #7
                       else:
                          lineout = lineout + "'" + tmpppn + " -> " + subrec['Event']['EventData']['NewProcessName'] + "'"+coldelimiter  #7
                    except:
                       lineout = lineout + "'" + tmpppn + " -> " + subrec['Event']['EventData']['NewProcessName'] + "'"+coldelimiter  #7
                    lineout = lineout + ""+coldelimiter #8
                    lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                    lineout = lineout + "'" + channel + "'"+coldelimiter  #10
                    lineout = lineout + "'" + infile + "'"   #11
                    lineout = lineout + "\n"
                    #print(f'{lineout}')
                    outfile.write(lineout)
              except:
                 parseproblem(subrec,outfile)         
        #--------------------------------------------------------------------------------------------------------------------------------                   
        if eventid == 7030 or eventid == 7040 or eventid == 7045:
          if channel == "System":
             try:
                printjson(subrec) 
                address = ''
                lineout = "'" + str(eventid) + "'"+coldelimiter      #1
                lineout = lineout + "'" + computer + "'"+coldelimiter  #2
                lineout = lineout + "'" + systemtime + "'"+coldelimiter #3
                lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'"+coldelimiter  #4
                lineout = lineout + ""+coldelimiter  #5
                lineout = lineout + ""+coldelimiter #6
                lineout = lineout + ""+coldelimiter #7
                lineout = lineout + ""+coldelimiter #8
                lineout = lineout + "'" + eventidtxt[str(eventid)] + "'"+coldelimiter  #9
                lineout = lineout + "'" + channel + "'"+coldelimiter  #10
                lineout = lineout + "'" + infile + "'"   #11
                lineout = lineout + "\n"
                #print(f'{lineout}')
                outfile.write(lineout)
             except:
                parseproblem(subrec,outfile)                    
                 
    print("end")
    outfile.close()
    if jsonfile == 1:    
       jsonoutfile.close()

def checkfile(inputfile):
   try:
      chkfile = open(inputfile, 'rb')
      data = chkfile.read(7)

      chkfile.close()
      #print(f'data: {data}')
      if data.decode("utf-8") == "ElfFile":
         return(1) 
      return(0)
   except:
      return(0)

def readconfig():
    #https://www.geeksforgeeks.org/python-reading-ini-configuration-files/
    configur = ConfigParser() 
    print (configur.read('config.ini')) 
  
    print ("Sections : ", configur.sections()) 
    print ("Installation Library : ", configur.get('installation','library')) 
    print ("Log Errors debugged ? : ", configur.getboolean('debug','log_errors')) 
    print ("Port Server : ", configur.getint('server','port')) 
    print ("Worker Server : ", configur.getint('server','nworkers')) 
    
def main(argv):
   inputfile = ''
   outputdir = '' 
   jsonfile=0
   coldelimiter = '|'
   try:
      opts, args = getopt.getopt(argv,"hi:o:d:j",["infile=","outdir="])
   except getopt.GetoptError:
      print ('pwrshell_evtx_parser.py -i <inputfile> -o <outputdir> -d <CSV Deliminator; | = default> -j')
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print ('pwrshell_evtx_parser.py -i <inputfile> -o <outputdir> -d <CSV Deliminator; | = default> -j {outfile a json file of all records}')
         sys.exit()
      elif opt in ("-i", "--infile"):
         inputfile = arg
      elif opt in ("-o", "--outdir"):
         outputdir = arg
      elif opt in ("-d", "--deliminator"):
         coldelimiter = arg
      elif opt in ("-j"):
         jsonfile = 1         

   if checkfile(inputfile) == 1:
      parseevtx(inputfile,outputdir,coldelimiter,jsonfile)
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main(sys.argv[1:])
