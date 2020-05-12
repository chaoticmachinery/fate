#!/usr/bin/env perl

#===================================================================================
# Basic Code Written by: Andreas Schuster
# Heavyly modified by: Keven Murphy
#
# Used for mass triage of systems, the script will parse the EventIDs and present
# the output in a CSV '|' delimited format. This allows for easy frequency analysis.
#
# Parses EVTX logs for event ids related to RDP.
#  
#
# Requirements:
# https://computer.forensikblog.de/en/2011/11/evtx-parser-1-1-1.html
#
# Author Notes:
# 1) To sort the output based on time use: (head -n1 rdpevtx.csv && sort -k3 -t\|  <(tail -n+2 rdpevtx.csv)) >  {filename}
#
# Mod Log:
#===================================================================================

#use strict;
# use warnings;
# use diagnostics;
use Getopt::Long;
use Parse::Evtx;
use Parse::Evtx::Chunk;
use Carp::Assert;
use IO::File 1.14;
use XML::Simple;
use Pod::Usage;
use Config::Tiny;
use File::Path;
use Cwd 'abs_path';
use Cwd;
use File::Find;
use File::Copy;
use File::Basename;
# Used for testing
#use Data::Dumper;
#use  Data::Dumper::Perltidy;

my $version = "1.1";
my $inputfile = "";
my $opt_help = "";
my $opt_man = ""; 

#https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
my %eventid =  ( 
    #Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx (Dst Host)
    '21'   => 'Remote Desktop Service: Session logon succeeded',
    '22'   => 'Remote Desktop Service: Shell start notification received',
    '23'   => 'Remote Desktop Service: Session logoff succeeded',
    '24'   => 'Remote Desktop Service: Session has been disconnected',
    '25'   => 'Remote Desktop Service: Session reconnect succeeded',
    '39'   => 'Session X has been disconnected, reason code Y',
    '40'   => 'Session X has been disconnected, reason code Z',
	#Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx (Dst Host)
    '261'  => 'Listener RDP-tcp received a connection',
    '1149' => 'User authentication succeeded  (NLA login)',
	#Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx (Dst Host)
	'102'  => 'The server has terminated main RDP connection with the client.',
	'103'  => 'The disconnect reason is X',
    '131'  => 'Server accepted a new TCP connection from client X',
    '140'  => 'A connection from the client computer with an IP address of xxx.xxx.xxx.xxx failed because the user name or password is not correct.',
	#Security.evtx (Dst Host)
    '4624' => 'An account was successfully logged on',
    '4625' => 'An account failed to log on',
    '4634' => 'An account was logged off',
    '4647' => 'User initiated logoff',
	'4648' => 'A logon was attempted using explicit credentials.',
    '4778' => 'A session was reconnected to a Windows Station',
    '4779' => 'A session was disconnected from a Windows Station',
	#System.evtx  (Dst Host)
    '56'   => 'The Terminal Server security layer detected an error in the protocol stream and has disconnected the client',
    '7001' => 'User Logon Notification for Customer Experience Improvement Program',
    '7002' => 'User Logoff Notification for Customer Experience Improvement Program',
    '9009' => 'The Desktop Windows Manager has exited eith code X',    
    '45058' => '',
	#Microsoft-Windows-TerminalServices-RDPClient/Operational.evtx  (Src host)
	'1024' => 'RDP ClientActiveX is trying to connect to the server ([Destination Host Name])',
	'1025' => 'RDP ClientActiveX has connected to the server.',
	'1026' => 'RDP ClientActiveX has been disconnected (Reason = [Reason]).',
	'1029' => 'Base64(SHA256(UserName)) is = [BASE64 Encoded SHA256 Hash Value of User Name]',
);


sub header2 {
    return "'EventID'|'ComputerName'|'TimeCreated'|'Security SID'|'UserID'|'Address'|'SessionID/Logon Type/Reason/IP:Port'|'Event'|'Channel (EVTX Log)'|'SRC File'\n";
};

sub squotes {
    my ($text) = @_;
    $text =~ s/\'/\"/g;
    return $text;
};

#=============================================================================================
# Addslash
#=============================================================================================
sub addslash {
    my ($path) = @_;

    my $lastchar =  substr($path,length($path)-1,1);
    if ($lastchar ne "/") {
	$path .= "/";
    }
    return($path);
}
#=============================================================================================

#=========================================================================================
# Process
#==========================================================================================
sub process {

#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_

     my $orglog = "";

     my($type) = "";
     open(FILE, $_) or die("Error reading file, stopped");
     read(FILE, $type, 7);
     close(FILE);
     if ($type eq "ElfFile") {
        #print "Reviewing $_ file\n";
        #Check to see if file name starts with the following:
        #Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
        #Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx
        #System
        #Security
        #Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
        #my $fnchk = 0;
        #if ($_ =~ /^Microsoft-Windows-TerminalServices-LocalSessionManager/) {
        #   $fnchk++;
        #}
        #if ($_ =~ /^Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/) {
        #   $fnchk++;
        #}    
        #if ($_ =~ /^Microsoft-Windows-TerminalServices-RemoteConnectionManager/) {
        #   $fnchk++;
        #}   
        #if ($_ =~ /^System/) {
        #   $fnchk++;
        #} 
        #if ($_ =~ /^Security/) {
        #   $fnchk++;
        #}          
        #if ($fnchk > 0) {
        #   rdpevtx($_);
        #}
        rdpevtx($_);
     }
}
#==========================================================================================
sub checkevtx {
    my ($xmldata) = @_;
    
    my $goodfile = 0;
    
    if ($xmldata =~ /Microsoft-Windows-TerminalServices-LocalSessionManager\/Operational/) {
        $goodfile++;
    }
    if ($xmldata =~ /Microsoft-Windows-RemoteDesktopServices-RdpCoreTS\/Operational/) {
        $goodfile++;
    }    
    if ($xmldata =~ /Microsoft-Windows-TerminalServices-RemoteConnectionManager\/Operational/) {
        $goodfile++;
    }   
    if ($xmldata =~ /^System/) {
        $goodfile++;
    } 
    if ($xmldata =~ /^Security/) {
        $goodfile++;
    }  
    if ($xmldata =~ /Microsoft-Windows-TerminalServices-RDPClient\/Operational/) {
        $goodfile++;
    } 
    return($goodfile);
}
    
sub rdpevtx {
    
    my ($inputfile) = @_;
    my $goodfile = 0;
    
    #Create the output file
    #my $sfilename = addslash($savedir).$savefilename;
    open(my $OUT, '>>', $sfilename) or die "Could not open file '$sfilename' $!";   
    

    my $fh = IO::File->new($inputfile, "r");
    if (!defined $fh) {
        print "Unable to open file: $!\n";
        exit 1;	
    }

    assert(defined $fh);
    my $file;
    $file = Parse::Evtx->new('FH' => $fh);
    if (!defined $file) {
        # if it's not a complete file, is it a chunk then?
        $file = Parse::Evtx::Chunk->new('FH' => $fh );
    }
    assert(defined $file);
    binmode(STDOUT, ":utf8");
    select((select(STDOUT), $|=1)[0]);

    eval {
        my $event = $file->get_first_event();

        while (defined $event) {
            my $data = $event->get_xml();
            my $xmldata = XMLin($data);
            
            if ($goodfile < 1) {
                 $goodfile = checkevtx($xmldata->{System}{Channel});
                 if ($goodfile == 0) {
                   last;
                 }
                 print "\tReviewing $inputfile for event ids...\n";           
            };
            #print  Dumper ($xmldata);
            #print "\n";

        
            #Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
            if ($xmldata->{System}{EventID} eq "21" ||
                $xmldata->{System}{EventID} eq "22" ||
                $xmldata->{System}{EventID} eq "23" ||
                $xmldata->{System}{EventID} eq "24" ||
                $xmldata->{System}{EventID} eq "25" ||
                $xmldata->{System}{EventID} eq "39" ||
                $xmldata->{System}{EventID} eq "40" ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-TerminalServices-LocalSessionManager\/Operational") {
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                    print $OUT "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    print $OUT "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    print $OUT "'".$xmldata->{UserData}{EventXML}{SessionID}."'|"; 
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";	    
                }
            }
            #Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
            if ($xmldata->{System}{EventID} eq "261") {
                print $OUT "'".$xmldata->{System}{EventID}."'|";  
                print $OUT "'".$xmldata->{System}{Computer}."'|";
                print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                print $OUT "|"; 
                print $OUT "|"; 
                print $OUT "|"; 
                #print "'".$xmldata->{UserData}{EventXML}{listenerName}."'|"; 
                print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                print $OUT "'".$xmldata->{System}{Channel}."'|";
                print $OUT "'".$inputfile."'";
                print $OUT "\n";	    
            }
            if ($xmldata->{System}{EventID} eq "1149") {
                print $OUT "'".$xmldata->{System}{EventID}."'|";  
                print $OUT "'".$xmldata->{System}{Computer}."'|";
                print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                #All tests (defined & exists) for key value that contains no data comes back positive
                #Hence have to detect HASH(0x) to find key with no value
                #May be a better way to do this
                my $param2;
                my $param1;
                my $param3;        
                if (length($xmldata->{UserData}{EventXML}{Param1}) > 10 && $xmldata->{UserData}{EventXML}{Param1} =~ /^HASH\(0x\w+\)$/) {  
                $param1 = "";
                } else {
                $param1 = $xmldata->{UserData}{EventXML}{Param1};
                }
                if (length($xmldata->{UserData}{EventXML}{Param2}) > 10 && $xmldata->{UserData}{EventXML}{Param2} =~ /^HASH\(0x\w+\)$/) { 
                $param2 = "";
                } else {
                $param2 = $xmldata->{UserData}{EventXML}{Param2};
                }
                if (length($xmldata->{UserData}{EventXML}{Param3}) > 10 && $xmldata->{UserData}{EventXML}{Param3} =~ /^HASH\(0x\w+\)$/) { 
                $param3 = "";
                } else {
                $param3 = $xmldata->{UserData}{EventXML}{Param3};
                }
                print $OUT "'".$param2."\\".$param1."'|"; #domain\\user id
                print $OUT "'From: ".$param3."'|"; #IP                
                #print $OUT "'".$xmldata->{UserData}{EventXML}{Param2}."\\"
                #              .$xmldata->{UserData}{EventXML}{Param1}."'|"; #domain\\user id
                #print $OUT "'From: ".$xmldata->{UserData}{EventXML}{Param3}."'|"; #IP
                print $OUT "|"; 
                print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|"; 
                print $OUT "'".$xmldata->{System}{Channel}."'|";
                print $OUT "'".$inputfile."'";
                print $OUT "\n";	    
            }
            #Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx
            #Event 102 & 103 not helpful
            #Need example 140
            if ($xmldata->{System}{EventID} eq "131" ||
                $xmldata->{System}{EventID} eq "140" ) {
                if ($xmldata->{System}{Provider}{Name} eq "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS") {
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                    print $OUT "''|";  # User
                    print $OUT "'From: ".$xmldata->{EventData}{Data}[1]{content}."'|";  #IP
                    print $OUT "''|"; 
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";	    
                }
            }
            #Security
            if ($xmldata->{System}{EventID} eq "4624" ) {
                if ($xmldata->{System}{Channel} eq "Security") {
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "''|"; #Security userid
                    # 6 TargetDomainname
                    # 5 TargetUserName
                    # 4 TargetUserSid
                    # 8 Logon Type
                    # 11 Workstation Name
                    # 18 IPaddress
                    # 19 Port
                    print $OUT "'".$xmldata->{EventData}{Data}[6]{content}."\\"
                                .$xmldata->{EventData}{Data}[5]{content}." ("
                                .$xmldata->{EventData}{Data}[4]{content}.")"."'|";
                    print $OUT "'".$xmldata->{EventData}{Data}[18]{content}
                                .":".$xmldata->{EventData}{Data}[19]{content}
                                ."->".$xmldata->{EventData}{Data}[11]{content}
                                ."'|"; #address
                    print $OUT "'Logon Type: ".$xmldata->{EventData}{Data}[8]{content}."'|"; 
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            if ($xmldata->{System}{EventID} eq "4625" ) {
                if ($xmldata->{System}{Channel} eq "Security") {         
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "''|"; #Security userid
                    # 6 TargetDomainname
                    # 5 TargetUserName
                    # 4 TargetUserSid
                    # 8 FailureReason
                    # 10 LogonType
                    # 13 WorkstationName
                    # 19 IPaddress
                    # 20 Port
                    print $OUT "'".$xmldata->{EventData}{Data}[6]{content}."\\"
                                .$xmldata->{EventData}{Data}[5]{content}."'|";
                    print $OUT "'From: ".$xmldata->{EventData}{Data}[13]{content}." ("
                                .$xmldata->{EventData}{Data}[19]{content}
                                .":".$xmldata->{EventData}{Data}[20]{content}
                                .")'|"; #address
                    print $OUT "'Logon Type: ".$xmldata->{EventData}{Data}[10]{content}
                            ."  Failure Reason: ".$xmldata->{EventData}{Data}[8]{content}."'|"; 
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }            
            if ($xmldata->{System}{EventID} eq "4634" ) {
                if ($xmldata->{System}{Channel} eq "Security") {
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "''|"; #Security userid
                    # 3 TargetDomainname
                    # 1 TargetUserName
                    # 0 TargetUserSid
                    # 4 LogonType
                    print $OUT "'".$xmldata->{EventData}{Data}[2]{content}."\\"
                            .$xmldata->{EventData}{Data}[1]{content}." ("
                            .$xmldata->{EventData}{Data}[0]{content}.")"."'|";
                    print $OUT "''|"; #address
                    print $OUT "'Logon Type: ".$xmldata->{EventData}{Data}[4]{content}."'|"; 
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            # Need example 4778 & 4779
            if ($xmldata->{System}{EventID} eq "4647" ||
                $xmldata->{System}{EventID} eq "4778" ||
                $xmldata->{System}{EventID} eq "4779"  ) {
                if ($xmldata->{System}{Channel} eq "Security") {
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "''|"; #Security userid
                    # 3 TargetDomainname
                    # 1 TargetUserName
                    # 0 TargetUserSid
                    print $OUT "'".$xmldata->{EventData}{Data}[2]{content}."\\"
                            .$xmldata->{EventData}{Data}[1]{content}." ("
                            .$xmldata->{EventData}{Data}[0]{content}.")"."'|";
                    print $OUT "''|"; #address
                    print $OUT "''|";
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            if ($xmldata->{System}{EventID} eq "4648" ) {
                if ($xmldata->{EventData}{Data}[11]{content} =~ 'winlogon.exe$') {
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "''|"; #Security userid
                    # 6 TargetDomainname
                    # 5 TargetUserName
                    # 8 TargetServerName
                    # 11 Processname
                    # 12 IPaddress
                    # 13 Port
                    print $OUT "'".$xmldata->{EventData}{Data}[6]{content}."\\"
                                  .$xmldata->{EventData}{Data}[5]{content}."'|";
                    print $OUT "''|"; #address
                    print $OUT "'IP:Port: ".$xmldata->{EventData}{Data}[12]{content}
                                           .":".$xmldata->{EventData}{Data}[13]{content}
                                           ." -> ".$xmldata->{EventData}{Data}[8]{content}
                                           ."'|"; 
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            #Microsoft-Windows-TerminalServices-RDPClient/Operational.evtx
            if ($xmldata->{System}{EventID} eq "1024"  ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-TerminalServices-RDPClient\/Operational") { 
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";  
                    print $OUT "'Connect to: ".$xmldata->{EventData}{Data}[1]{content}."'|";  #address
                    print $OUT "''|"; #sessionid
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            if ($xmldata->{System}{EventID} eq "1025"  ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-TerminalServices-RDPClient\/Operational") {             
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";  
                    print $OUT "'".$xmldata->{EventData}{Data}[1]{content}."'|";  #address
                    print $OUT "''|"; #sessionid
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            if ($xmldata->{System}{EventID} eq "1026"  ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-TerminalServices-RDPClient\/Operational") {                   
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";  
                    print $OUT "''|";  #address
                    print $OUT "'".$xmldata->{EventData}{Data}[0]{content}.": "
                                .$xmldata->{EventData}{Data}[1]{content}
                                ."'|"; #sessionid
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            if ($xmldata->{System}{EventID} eq "1029"  ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-TerminalServices-RDPClient\/Operational") {       
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";  
                    print $OUT "''|";  #address
                    print $OUT "''|"; #sessionid
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }	    
    
            #System
            #need example 9009
            if ($xmldata->{System}{EventID}{content} eq "56" ||
                $xmldata->{System}{EventID}{content} eq "9009" ) {
                if ($xmldata->{System}{Channel} eq "System") {                 
                    print $OUT "'".$xmldata->{System}{EventID}{content}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "''|"; #security userid
                    print $OUT "''|"; #user
                    print $OUT "''|"; #address
                    my $tmp = $xmldata->{EventData}{Data};
                    $tmp =~ tr/\r\n//d;
                    print $OUT "'".$tmp."'|"; #sessionid
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}{content}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";
                    print $OUT "\n";
                }
            }
            if ($xmldata->{System}{EventID} eq "7001" ||
                $xmldata->{System}{EventID} eq "7002" ) {
                if ($xmldata->{System}{Provider}{Name} eq "Microsoft-Windows-Winlogon") {
                    print $OUT "'".$xmldata->{System}{EventID}."'|";  
                    print $OUT "'".$xmldata->{System}{Computer}."'|";
                    print $OUT "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    print $OUT "'".$xmldata->{System}{Security}{UserID}."'|";
                    print $OUT "'".$xmldata->{EventData}{Data}[1]{content}."'|";  #UserSID
                    print $OUT "''|"; #address
                    print $OUT "''|"; #sessionid
                    print $OUT "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    print $OUT "'".$xmldata->{System}{Channel}."'|";
                    print $OUT "'".$inputfile."'";	
                    print $OUT "\n";
                }
            }	            
            #print  Dumper ($xmldata);
            #print "\n";
            $event = $file->get_next_event();
        }
    };  
    $fh->close();
    close($OUT);
}

#=============================================================================================

GetOptions ("mntdrive=s"   => \$mntdrive      # output directory
           ) ||  pod2usage(-verbose => 0);
		      
    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory arguement '--mntdrive' is missing}
		 -exitval => 1,
		 -verbose => 1 }
	) unless ($mntdrive);
	
#=============================================================================================
# Read in config file
#=============================================================================================
$Config = Config::Tiny->read( $config );


if ($config eq ""){
  ($filename, $directories, $suffix) = fileparse(abs_path($0));
  $config = $directories."plugins.ini";
}

my $Config = Config::Tiny->read( $config );
if (defined $config) {
    $savedirconfig=$Config->{rdpevtx}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $thread=$Config->{rdpevtx}->{thread};
    $savefilename=$Config->{rdpevtx}->{savefilename};
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================	
	
#=============================================================================================
# Setup environment to begin work
#=============================================================================================
my $dircwd = getcwd();
my $abs_path = abs_path();
chomp($dircwd);

$savedir = $dircwd . "/" . $savedirconfig;
$analyzemftopts =~ s/SAVEDIR/$savedir/g;

$dir = $dircwd;
#$mftfilename = $dir."/\$MFT";
#$md5logfilename =  $savedir . "/md5log";
print "Reviewing mount point for EVTX files: $mntdrive\n";
print "Saving RDPEVTX output file to: $savedir\n";
print "Config File Used: $config\n";
#print "Note: This plugin will recreate the directory structure in the save directory for any processed file.\n";
#chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

#print "Note: EVTX files names must start with the following:\n";
#print "\tMicrosoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx\n";
#print "\tMicrosoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx\n";
#print "\tSystem\n";
#print "\tSecurity\n";
#print "\tMicrosoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx\n";



#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create $savedir\n";
}
#=============================================================================================

#=============================================================================================
# Start of plugin code
#=============================================================================================	

#Create the output file
$sfilename = addslash($savedir).$savefilename;
open(my $fh, '>', $sfilename) or die "Could not open file '$sfilename' $!";
print $fh header2;
close($fh);


#Find the EVTX
print "Searchng for EVTX files.\n";
find(\&process, $mntdrive);	


__END__

=head1 rdp_etvx_parse.pl

Image device

=head1 SYNOPSIS

wmi_etvx_parse.pl [options] [file ...]

Options:

--file    EVTX log (MANDATORY)

--help       Brief help message

--man        Full documentation

=head1 OPTIONS

=over 8

=item B<-help>

Print a brief help message and exits.

=item B<-man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<wrdp_etvx_parse.pl> parse out the events for multiple evtx logs for RDP artifacts.
=cut
