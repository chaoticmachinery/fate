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

#Config ini
from configparser import ConfigParser 

version = '0.1a'


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
        print(res)
        
        
rdpdisconnect = {
    '0' : '“No additional information is available.” (Occurs when a user informally X’es out of a session, typically paired with Event ID 24)',
    '5' : '“The client’s connection was replaced by another connection.” (Occurs when a user reconnects to an RDP session, typically paired with an Event ID 25)',
    '11' : '“User activity has initiated the disconnect.” (Occurs when a user formally initiates an RDP disconnect, for example via the Windows Start Menu Disconnect option.)',
    '12' : ''
}
        
        
eventidtxt = { 
    #Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx (Dst Host)
    '21' : 'Remote Desktop Service: Session logon succeeded',
    '22' : 'Remote Desktop Service: Shell start notification received',
    '23' : 'Remote Desktop Service: Session logoff succeeded',
    '24' : 'Remote Desktop Service: Session has been disconnected',
    '25' : 'Remote Desktop Service: Session reconnect succeeded',
    '39' : 'Session X has been disconnected, reason code Y',
    '40' : 'Session X has been disconnected, reason code Z',
	#Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx (Dst Host)
    '261' : 'Listener RDP-tcp received a connection',
    '1149' : 'User authentication succeeded  (NLA login)',
	#Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx (Dst Host)
	'102'  : 'The server has terminated main RDP connection with the client.',
	'103'  : 'The disconnect reason is X',
    '131'  : 'Server accepted a new TCP connection from client X',
    '140'  : 'A connection from the client computer with an IP address of xxx.xxx.xxx.xxx failed because the user name or password is not correct.',
	#Security.evtx (Dst Host)
    '4624' : 'An account was successfully logged on',
    '4625' : 'An account failed to log on',
    '4634' : 'An account was logged off',
    '4647' : 'User initiated logoff',
	'4648' : 'A logon was attempted using explicit credentials.',
    '4778' : 'A session was reconnected to a Windows Station',
    '4779' : 'A session was disconnected from a Windows Station',
	#System.evtx  (Dst Host)
    '56' : 'The Terminal Server security layer detected an error in the protocol stream and has disconnected the client',
    '7001' : 'User Logon Notification for Customer Experience Improvement Program',
    '7002' : 'User Logoff Notification for Customer Experience Improvement Program',
    '9009' : 'The Desktop Windows Manager has exited eith code X',    
    '45058' : '',
	#Microsoft-Windows-TerminalServices-RDPClient/Operational.evtx  (Src host)
	'1024' : 'RDP ClientActiveX is trying to connect to the server ([Destination Host Name])',
	'1025' : 'RDP ClientActiveX has connected to the server.',
	'1026' : 'RDP ClientActiveX has been disconnected (Reason = [Reason]).',
	'1029' : 'Base64(SHA256binary(UTF-16LE(UserName)) is = Userid',
}


#https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/

def rdpevtx(infile,outdir):  
    outfilenametmp = os.path.basename(infile) + ".csv"
    drive,outfiledir = os.path.splitdrive(os.path.dirname(infile))
    
    #Make Dir
    harddir = outdir +os.sep+ outfiledir
    outfilename = harddir +os.sep+ outfilenametmp
    print(f'Out Info: {outfilename}') 
    os.makedirs(harddir, exist_ok=True)
    
    header = "'EventID'|'ComputerName'|'TimeCreated'|'Security SID'|'UserID'|'Address'|'SessionID/Logon Type/Reason/IP:Port'|'Event'|'Channel (EVTX Log)'|'SRC File'\n"
    #create file
    outfile = open(outfilename,'w')
    outfile.write(header)
      
    parser = PyEvtxParser(infile)
    print(f'Working on: {infile}')    
    for record in parser.records_json():
        subrec = json.loads(record["data"])
        
        lineout = ""
        eventid = subrec['Event']['System']['EventID']
        channel = subrec['Event']['System']['Channel']
        computer = subrec['Event']['System']['Computer']
        systemtime = subrec['Event']['System']['TimeCreated']['#attributes']['SystemTime']
        
        #print(subrec['Event']['UserData']['EventXML'].keys())
        #printjson(subrec)
        
        if eventid == 21 or eventid == 22 or eventid == 23 or eventid == 24 or eventid == 25:
           if channel == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":
              #printjson(subrec) 
              address = ''
              lineout = "'" + str(eventid) + "'|"      #1
              lineout = lineout + "'" + computer + "'|"  #2
              lineout = lineout + "'" + systemtime + "'|" #3
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"  #4
              lineout = lineout + "'" + subrec['Event']['UserData']['EventXML']['User'] + "'|" #5
              #Shitty way to get the value of Address from JSON but could not get it pulled any other way
              #for x in retrieve_nested_value(subrec, "Address"):
              #    lineout = lineout + "'From: " + x + "'|"
                  
              if 'Address' in subrec['Event']['UserData']['EventXML'].keys(): 
                 address = (subrec['Event']['UserData']['EventXML']['Address'])
              else:
                 address = '' #or empty string 
              lineout = lineout + "'From: " + address + "'|"  #6
              lineout = lineout + "'" + str(subrec['Event']['UserData']['EventXML']['SessionID']) + "'|"   #7
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"  #8
              lineout = lineout + "'" + channel + "'|"  #9
              lineout = lineout + "'" + infile + "'"  #10
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)

        if eventid == 39:
           if channel == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"   #1
              lineout = lineout + "'" + computer + "'|"   #2
              lineout = lineout + "'" + systemtime + "'|"   #3
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"  #4
              lineout = lineout + "|"  #5
              lineout = lineout + "|"  #6
              #lineout = lineout + "'" + "Session: " + str(subrec['Event']['UserData']['EventXML']['Session']) 
              #lineout = lineout + "  Reason: " + rdpdisconnect[str(subrec['Event']['UserData']['EventXML']['Reason'])] + "'|"
              lineout = lineout + "'" + "Session: " + str(subrec['Event']['UserData']['EventXML']['TargetSession'])   #7
              lineout = lineout + "  Source: " + str(subrec['Event']['UserData']['EventXML']['Source']) + "'|"        #7      
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"  #8
              lineout = lineout + "'" + channel + "'|"  #9
              lineout = lineout + "'" + infile + "'"  #10
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)

        if eventid == 40:
           if channel == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"   #1
              lineout = lineout + "'" + computer + "'|"  #2
              lineout = lineout + "'" + systemtime + "'|"   #3
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"  #4
              lineout = lineout + "|"  #5
              lineout = lineout + "|"  #6
              lineout = lineout + "'" + "Session: " + str(subrec['Event']['UserData']['EventXML']['Session'])  #7
              lineout = lineout + "  Reason: " + rdpdisconnect[str(subrec['Event']['UserData']['EventXML']['Reason'])] + "'|"  #7
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"  #8
              lineout = lineout + "'" + channel + "'|"  #9
              lineout = lineout + "'" + infile + "'"   #10
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)
        #--------------------------------------------------------------------------------------------------------------------------------          
        if eventid == 261:
           if channel == "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'"  
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)


        if eventid == 1149:
           if channel == "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational":
              #printjson(subrec)
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "'" + subrec['Event']['UserData']['EventXML']['Param2'] + "\\" + subrec['Event']['UserData']['EventXML']['Param1'] + "'|"
              lineout = lineout + "'" + "Src IP: " + subrec['Event']['UserData']['EventXML']['Param3'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'"   
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)      
        #---------------------------------------------------------------------------------------------------------------------------------
        if eventid == 131 or eventid == 140:
           if channel == "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "'From: " + subrec['Event']['EventData']['ClientIP'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'"  
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)
        #---------------------------------------------------------------------------------------------------------------------------------
        if eventid == 4624:
           if channel == "Security":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"  #1
              lineout = lineout + "'" + computer + "'|"     #2
              lineout = lineout + "'" + systemtime + "'|"       #3
              lineout = lineout + "|" #Security UserID     #4
                    # 6 TargetDomainname
                    # 5 TargetUserName
                    # 4 TargetUserSid
                    # 8 Logon Type
                    # 11 Workstation Name
                    # 18 IPaddress
                    # 19 Port
              lineout = lineout + "'" + subrec['Event']['EventData']['TargetDomainName'] + "\\" + subrec['Event']['EventData']['TargetUserName']
              lineout = lineout + " (" + subrec['Event']['EventData']['TargetUserSid'] +") " + "'|"             #5
              lineout = lineout + "'" + subrec['Event']['EventData']['IpAddress'] + ":" + subrec['Event']['EventData']['IpPort'] + " -> "
              lineout = lineout + subrec['Event']['EventData']['WorkstationName'] + "'|"       #6
              lineout = lineout + "'Logon Type: " + str(subrec['Event']['EventData']['LogonType']) + "'|"       #7
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"   #8
              lineout = lineout + "'" + channel + "'|"   #9
              lineout = lineout + "'" + infile + "'"     #10
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)  
              
        if eventid == 4625:
           if channel == "Security":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "|" #Security UserID
                    # 6 TargetDomainname
                    # 5 TargetUserName
                    # 4 TargetUserSid
                    # 8 FailureReason
                    # 10 LogonType
                    # 13 WorkstationName
                    # 19 IPaddress
                    # 20 Port
              lineout = lineout + "'" + subrec['Event']['EventData']['TargetDomainName'] + "\\" + subrec['Event']['EventData']['TargetUserName']
              lineout = lineout + " (" + subrec['Event']['EventData']['TargetUserSid'] +") " + "'|" 
              lineout = lineout +"'From: " + subrec['Event']['EventData']['WorkstationName'] + " (" + subrec['Event']['EventData']['IpAddress'] + ":" + subrec['Event']['EventData']['IpPort'] + ")'|"
              lineout = lineout + "'Logon Type: " + str(subrec['Event']['EventData']['LogonType']) + "  Failure Reason: " + subrec['Event']['EventData']['FailureReason']+ "'|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'"    
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout) 
              
        if eventid == 4634 :
           if channel == "Security":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"    #1
              lineout = lineout + "'" + computer + "'|"  #2
              lineout = lineout + "'" + systemtime + "'|"   #3
              lineout = lineout + "|" #Security UserID    #4
              # 3 TargetDomainname
              # 1 TargetUserName
              # 0 TargetUserSid
              # 4 LogonType
              lineout = lineout + "'" + subrec['Event']['EventData']['TargetDomainName'] + "\\" + subrec['Event']['EventData']['TargetUserName']
              lineout = lineout + " (" + subrec['Event']['EventData']['TargetUserSid'] +") " + "'|"   #5
              lineout = lineout + "|"   #6
              lineout = lineout + "'Logon Type: " + str(subrec['Event']['EventData']['LogonType']) + "'|"  #7
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"  #8
              lineout = lineout + "'" + channel + "'|"   #9
              lineout = lineout + "'" + infile + "'"     #10
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)       

        if eventid == 4647:
           if channel == "Security":
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"    #EventID
              lineout = lineout + "'" + computer + "'|"  #ComputerName
              lineout = lineout + "'" + systemtime + "'|"   #Time Created
              lineout = lineout + "|" #Security UserID    #4
              # 3 TargetDomainname
              # 1 TargetUserName
              # 0 TargetUserSid
              # 4 LogonType
              lineout = lineout + "'" + subrec['Event']['EventData']['TargetDomainName'] + "\\" + subrec['Event']['EventData']['TargetUserName']
              lineout = lineout + " (" + subrec['Event']['EventData']['TargetUserSid'] +") " + "'|"    #UserID
              lineout = lineout + "|"    #Address
              lineout = lineout + "|" #SessionID/Logon Type/Reason/IP:Port
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"  #8
              lineout = lineout + "'" + channel + "'|"   #9
              lineout = lineout + "'" + infile + "'"     #10
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)     
              
        if eventid == 4648:
           if channel == "Security":
              if search('winlogon.exe$', subrec['Event']['EventData']['ProcessName']): 
                 #printjson(subrec) 
                 lineout = "'" + str(eventid) + "'|" #EventID
                 lineout = lineout + "'" + computer + "'|" #ComputerName
                 lineout = lineout + "'" + systemtime + "'|" #Time Created
                 lineout = lineout + "|" #Security UserID
                        # 6 TargetDomainname
                        # 5 TargetUserName
                        # 8 TargetServerName
                        # 11 Processname
                        # 12 IPaddress
                        # 13 Port
                 lineout = lineout + "'Subject: " + subrec['Event']['EventData']['SubjectDomainName'] + "\\" + subrec['Event']['EventData']['SubjectUserName']
                 lineout = lineout + " (LogonID: " + subrec['Event']['EventData']['SubjectUserSid'] +") "                                                 
                 lineout = lineout + "Target: "+ subrec['Event']['EventData']['TargetDomainName'] + "\\" + subrec['Event']['EventData']['TargetUserName'] + "'|"   #UserID
                 lineout = lineout + "|'" + subrec['Event']['EventData']['IpAddress'] + ":" + subrec['Event']['EventData']['IpPort']
                 lineout = lineout + "    Target: " + subrec['Event']['EventData']['TargetServerName'] + " (" + subrec['Event']['EventData']['TargetInfo'] +") " + "'|" #Address
                 lineout = lineout + "|'Process: " + subrec['Event']['EventData']['ProcessName'] + " ("+subrec['Event']['EventData']['ProcessId'] + ")'|"  #SessionID/Logon Type/Reason/IP:Port
                 lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|" 
                 lineout = lineout + "'" + channel + "'|"
                 lineout = lineout + "'" + infile + "'" 
                 lineout = lineout + "|python"
                 lineout = lineout + "\n"
                 #print(f'{lineout}')
                 outfile.write(lineout)                
 
        if eventid == 4778 or eventid == 4779:
           if channel == "Security": 
              #printjson(subrec) 
              lineout = "'" + str(eventid) + "'|"  #EventID
              lineout = lineout + "'" + computer + "'|"   #ComputerName
              lineout = lineout + "'" + systemtime + "'|"  #Time Created
              lineout = lineout + "|" #Security UserID
                    # 3 TargetDomainname
                    # 1 TargetUserName
                    # 0 TargetUserSid
              lineout = lineout + "'" + subrec['Event']['EventData']['AccountDomain'] + "\\" + subrec['Event']['EventData']['AccountName']
              lineout = lineout + " (LogonID: " + subrec['Event']['EventData']['LogonID'] +") " + "'|"   #UserID
              lineout = lineout + "|'" + subrec['Event']['EventData']['ClientName'] + " (" + subrec['Event']['EventData']['ClientAddress'] +") " + "'|" #Address
              lineout = lineout + "|'" + subrec['Event']['EventData']['SessionName'] + "'|"  #SessionID/Logon Type/Reason/IP:Port
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|" 
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'" 
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout) 
              
         #---------------------------------------------------------------------------------------------------------------------------------

        if eventid == 1024:
           if channel == "Microsoft-Windows-TerminalServices-RDPClient/Operational": 
              #printjson(subrec)
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "'Connect to: " + subrec['Event']['EventData']['Value'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'" 
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)

        if eventid == 1025:
           if channel == "Microsoft-Windows-TerminalServices-RDPClient/Operational": 
              #printjson(subrec)
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'"  
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)

        if eventid == 1026:
           if channel == "Microsoft-Windows-TerminalServices-RDPClient/Operational": 
              #printjson(subrec)
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + subrec['Event']['EventData']['CustomLevel'] + ": " + subrec['Event']['EventData']['Name'] + " " + str(subrec['Event']['EventData']['Value']) +"'|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'" 
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)

        if eventid == 1029:
           if channel == "Microsoft-Windows-TerminalServices-RDPClient/Operational": 
              #printjson(subrec)
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "Userid Base64 Hash: " + subrec['Event']['EventData']['TraceMessage'] + "'|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'"   
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)

         #---------------------------------------------------------------------------------------------------------------------------------
         
        if eventid == 56:
           if channel == "System": 
              printjson(subrec)
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'" 
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)

        #System 9009 Eventid
        #if '#text' in subrec['Event']['System']['EventID'].keys(): 
        #   eventidsys = subrec['Event']['System']['EventID']['#text']
        #else:
        #   eventidsys = 0 #or empty string
        #if channel == "System": 
           #print(f'{subrec['Event']['System'].keys()}')
        #   print(subrec['Event']['UserData']['EventXML'].keys())
        #if eventidsys == "9009":
        #   if channel == "System": 
        #      if subrec['Event']['System']['Provider']['attributes']['Name'] == 'Desktop Window Manager': 
        #         printjson(subrec)
        #         lineout = "'" + str(eventid) + "'|"
        #         lineout = lineout + "'" + computer + "'|"
        #         lineout = lineout + "'" + systemtime + "'|"
        #         lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
        #         lineout = lineout + "|"
        #         lineout = lineout + "|"
        #         lineout = lineout + "|"
        #         lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
        #         lineout = lineout + "'" + channel + "'|"
        #         lineout = lineout + "'" + infile + "'" 
        #         lineout = lineout + "|python"
        #         lineout = lineout + "\n"
                 #print(f'{lineout}')
        #         outfile.write(lineout)


         #---------------------------------------------------------------------------------------------------------------------------------

        if eventid == 7001 or eventid == 7002:
           if channel == "Microsoft-Windows-Winlogon/Operational": 
              #printjson(subrec)
              lineout = "'" + str(eventid) + "'|"
              lineout = lineout + "'" + computer + "'|"
              lineout = lineout + "'" + systemtime + "'|"
              lineout = lineout + "'" + subrec['Event']['System']['Security']['#attributes']['UserID'] + "'|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "|"
              lineout = lineout + "'" + eventidtxt[str(eventid)] + "'|"
              lineout = lineout + "'" + channel + "'|"
              lineout = lineout + "'" + infile + "'"  
              lineout = lineout + "|python"
              lineout = lineout + "\n"
              #print(f'{lineout}')
              outfile.write(lineout)
              
        #print(subrec)
        #print(subrec['Event']['UserData']['EventXML'])
        #print(subrec['Event']['UserData']['EventXML']['Address'])              
              
              
              
        
        #print(f'------------------------------------------')
    print("end")
    outfile.close()

def checkfile(inputfile):
   chkfile = open(inputfile, 'rb')
   data = chkfile.read(7)

   chkfile.close()
   #print(f'data: {data}')
   if data.decode("utf-8") == "ElfFile":
      return(1) 
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
   try:
      opts, args = getopt.getopt(argv,"hi:o:",["infile=","outdir="])
   except getopt.GetoptError:
      print ('rdp_evtx_parse.py -i <inputfile> -o <outputdir>')
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print ('rdp_evtx_parse.py -i <inputfile> -o <outputdir>')
         sys.exit()
      elif opt in ("-i", "--infile"):
         inputfile = arg
      elif opt in ("-o", "--outdir"):
         outputdir = arg

   if checkfile(inputfile) == 1:
      rdpevtx(inputfile,outputdir)
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main(sys.argv[1:])
