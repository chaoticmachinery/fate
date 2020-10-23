#!/usr/bin/env perl

#===================================================================================
# Basic Code Written by: Andreas Schuster
# Heavyly modified by: Keven Murphy
#
# Used for mass triage of systems, the script will parse the EventIDs and present
# the output in a CSV '|' delimited format. This allows for easy frequency analysis.
#
# Parses EVTX logs for event ids related to Powershell.
#  
#
# Requirements:
# https://computer.forensikblog.de/en/2011/11/evtx-parser-1-1-1.html
#
# References:
# https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html
# https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf
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
use threads;
use threads::shared;
use Thread::Queue;

# Used for testing
use Data::Dumper;
use  Data::Dumper::Perltidy;

my $version = "1.0";
my $inputfile = "";
my $opt_help = "";
my $opt_man = ""; 
my @fileslist;
my $flcnt = 0;
my $process_q = Thread::Queue -> new();

my %eventid =  ( 
    #Windows PowerShell && Microsoft-Windows-Powersell%4Operational.evtx (Dst Host)
    #'200'
    #'400' => 'Start of any local or remote PowerShell activity',
    #'403' => 'End of PowerShell activity',
    #'500' => 'Requires $LogCommandLifeCycleEvent = $true in profile.ps1; This event is largely useless since it can be bypassed with the -nop command line switch',
    #'501' => 'Requires $LogCommandLifeCycleEvent = $true in profile.ps1; This event is largely useless since it can be bypassed with the -nop command line switch',
    #'600'   => 'Onset of PowerShell remoting activity on both src and dest systems',
    #'800' => 'Shows pipeline execution details.'
    #
    '400'   => 'Start of any local or remote PowerShell activity',
    '403'   => 'End of PowerShell activity',
    '600'   => 'Onset of PowerShell remoting activity on both src and dest systems',
    '4100'  => 'Error Message',
    '4103'  => '',
    '4104'  => 'Scriptblock text',
	#System.evtx  (Dst Host)
	'7040' => 'Recorded when PowerShell remoting is enabled',
    '7030' => '',
    '7045' => 'Service Installed',
    #WinRM
    '6'    => 'Remote handling activity is started on the client system, includes the destination address',
    '142'  => 'If WinRM is disabled on the remote server, this event is recorded when the client attempts to initiate a remote shell connection.',
    '169'  => 'Authenication prior to PowerShell remoting on a accessed system',
    #Security
    #https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
    '4688' => 'Indicates the execution of PowerShell console or interpreter; “New Process Name”(powershell.exe), look for Creator Process ID to link what process launched what other processesb.4688 –SECURITY Log –What “Process Command Line” was executed for any ‘powershell.exe’ events',
);


# PowerShell Versions and OS:The ability to perform advanced logging of PowerShell is limited to certain operating systems and the versionsof PowerShellused.  Basic PowerShell logging is available for all versions of Windows 7, Server 2008 and above, but advanced auditing is limited to PowerShell 4 and 5.  The following lists the OS, log(s),andEvent ID’s for each operating system and PowerShell version to monitor.
#   Windows 7 and Server 2008and above:
#       PowerShell version 2thru 4, “Windows PowerShell”log –Event ID’s 400, 500, 501 and 800
#   Windows 8.1and Server 2012and above:
#       PowerShellversion 3 and4, “Windows PowerShell” log-Event ID’s 400, 500, 501 and 800
#       “Microsoft-Windows-PowerShell/Operational”log –Event ID 4104
#   Windows 7 and Server 2008 and above:
#       PowerShellversion 5, “Windows PowerShell” log-Event ID’s 200, 400, 500 and 501
#       “Microsoft-Windows-PowerShell/Operational”log –Event ID 4100, 4103 and 4104
#Note:There are other 4105 & 4106events, but they are of little value to security monitoringandVERY noisy

sub header2 {
    return "'EventID'|'ComputerName'|'TimeCreated'|'Security SID'|'Base64 Used'|'Data'|'SRC File'\n";
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

#=============================================================================================
# Process the files
#=============================================================================================
sub threadprocess2 {

    #my ($fn) = @_;

    my $cnt = 0;
    my $left = 0;
    my $pausecnt = 0;

    
    foreach $evtxfile (@filelist) {
      $process_q -> enqueue ( $evtxfile );
    }
    $process_q -> end();
    
    for (0..$maxthread) {
       threads -> create ( \&worker );
    }
    
    #Wait for threads to all finish processing.
    #foreach my $thr ( threads -> list() ) {
    #   $thr -> join();
    #}
    my @threadlist = threads->list(threads::running);
    my $num_threads = $#threadlist;
    print "Waiting for $num_threads to complete...\n";
    while($num_threads != -1) {
      sleep(1);
      foreach $thr (threads->list) {
        @threadlist = ();
        # Don't join the main thread or ourselves
        if ($thr->tid && !threads::equal($thr, threads->self)) {
            $thr->join;
        }
      }
      @threadlist = threads->list;
      $num_threads = $#threadlist;
      print "Waiting for $num_threads to complete...\n";
    }

}

sub worker {

  while ( my $evtxfileworker = $process_q -> dequeue() )
  {
    chomp ( $evtxfileworker );
    print "\tThread " .threads -> self() -> tid(). ": Reviewing $evtxfileworker\n";
    
    eval {
       parseevtx($evtxfileworker);
    };
    if ($process_q ->pending() ne "") {
        print "Number of files left to review: ".$process_q ->pending()."\n";
     } else {
    }
  }

}


#=========================================================================================
# Process
#==========================================================================================
sub process {

#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_
  
     my $orglog = "";

     my($type) = "";
     open(FILE, $_);# or die("Error reading file, stopped");
     read(FILE, $type, 7);
     close(FILE);
     if ($type eq "ElfFile") {
	   $filelist[$flcnt] = $File::Find::name;
	   $flcnt++;
	   #EVTX($_);
     }
	 #print "FileCNT: $flcnt\n";
}
#==========================================================================================
sub checkevtx {
    my ($xmldata) = @_;
    
    my $goodfile = 0;
    
    if ($xmldata =~ /Microsoft-Windows-PowerShell\/Operational/) {
        $goodfile++;
    }
 
    if ($xmldata =~ /^System/) {
        $goodfile++;
    } 
    if ($xmldata =~ /^Security/) {
        $goodfile++;
    }  
    if ($xmldata =~ /Microsoft-Windows-WinRM\/Operational/) {
        $goodfile++;
    }
    if ($xmldata =~ /Windows PowerShell/) {
        $goodfile++;
    }      
    return($goodfile);
}
    
sub parseevtx {
    
    my ($inputfile) = @_;
    my $goodfile = 0;
    #my $tid = threads->tid();
    #print "Thread id: $tid\n";
    
    #Create the output file
    #my $sfilename = addslash($savedir).$savefilename;
    my($infilename, $indirs, $insuffix) = fileparse($inputfile);
    $savefile = addslash($savedir).$infilename.".csv";
    #open(my $OUT, '>>', $sfilename) or die "Could not open file '$sfilename' $!";   
    open(my $OUT, '>', $savefile) or die "Could not open file '$savefile' $!";
    binmode $OUT, ":encoding(UTF-8)";
    print $OUT header2;

    my $fh = IO::File->new($inputfile, "r");
    if (!defined $fh) {
        print "Unable to open file: $!\n";
        close($OUT);
        return;
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
	        my $outline = "";
	        
            if ($goodfile < 1) {
                 $goodfile = checkevtx($xmldata->{System}{Channel});
                 if ($goodfile == 0) {
                   last;
                 }
                 #print "\tReviewing $inputfile for event ids...\n";           
            };
            #print  Dumper ($xmldata);
            #print "\n";

#--Windows PowerShell------------------------------------------------------------------------------        
            #Windows PowerShell.evtx
            #Need example of 200, 500, 501, 800
            if  ($xmldata->{System}{EventID}{content} eq "200" ||
                 $xmldata->{System}{EventID}{content} eq "400" ||
                 $xmldata->{System}{EventID}{content} eq "403" ||
                 $xmldata->{System}{EventID}{content} eq "500" ||
                 $xmldata->{System}{EventID}{content} eq "501" ||
                 $xmldata->{System}{EventID}{content} eq "600" ) {
                if ($xmldata->{System}{Channel} eq "Windows PowerShell") {
                    $outline .= "'".$xmldata->{System}{EventID}{content}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "''|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    my $pwrdata = lc($xmldata->{EventData}{Data});
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					#if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					#    $outline .= "'Y'|";
					#  } else {
					    $outline .= "'N'|";
					#}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }            
            if  ($xmldata->{System}{EventID}{content} eq "800" ) {
                if ($xmldata->{System}{Channel} eq "Windows PowerShell") {
                    $outline .= "'".$xmldata->{System}{EventID}{content}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "''|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    my $pwrdata = lc($xmldata->{EventData}{Data});
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }  
            
#--Microsoft-Windows-PowerShell%4Operational------------------------------------------------------------------------------        
            #Microsoft-Windows-PowerShell%4Operational.evtx
            if  ($xmldata->{System}{EventID} eq "4100" ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-PowerShell\/Operational") {
                    $outline .= "'".$xmldata->{System}{EventID}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "'".$xmldata->{System}{Security}{UserID}."'|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    my $pwrdata = lc($xmldata->{EventData}{Data}[0]{content});
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }
            
            if  ($xmldata->{System}{EventID} eq "4103" ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-PowerShell\/Operational") {
                    $outline .= "'".$xmldata->{System}{EventID}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "'".$xmldata->{System}{Security}{UserID}."'|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    my $pwrdata = lc($xmldata->{EventData}{Data}[0]{content});
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }
            if  ($xmldata->{System}{EventID} eq "4104" ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-PowerShell\/Operational") {
                    $outline .= "'".$xmldata->{System}{EventID}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "'".$xmldata->{System}{Security}{UserID}."'|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    my $pwrdata = lc($xmldata->{EventData}{Data}[2]{content});
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }
#--WINRM------------------------------------------------------------------------------
            #Microsoft-Windows-WinRM/Operational
            if  ($xmldata->{System}{EventID} eq "6" ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-WinRM\/Operational") {
                    $outline .= "'".$xmldata->{System}{EventID}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "'".$xmldata->{System}{Security}{UserID}."'|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    my $pwrdata = lc($xmldata->{EventData}{Data}[0]{content});
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }
            if  ($xmldata->{System}{EventID} eq "142" ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-WinRM\/Operational") {
                    $outline .= "'".$xmldata->{System}{EventID}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "'".$xmldata->{System}{Security}{UserID}."'|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    #my $pwrdata = lc($xmldata->{EventData}{Data}[0]{content});
                    my $pwrdata = $xmldata->{EventData}{Data}[0]{Name}.": ".$xmldata->{EventData}{Data}[0]{content};
                    $pwrdata .= "\t".$xmldata->{EventData}{Data}[1]{Name}.": ".$xmldata->{EventData}{Data}[1]{content};
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }            
            if  ($xmldata->{System}{EventID} eq "169" ) {
                if ($xmldata->{System}{Channel} eq "Microsoft-Windows-WinRM\/Operational") {
                    $outline .= "'".$xmldata->{System}{EventID}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "'".$xmldata->{System}{Security}{UserID}."'|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    #my $pwrdata = lc($xmldata->{EventData}{Data}[0]{content});
                    my $pwrdata = $xmldata->{EventData}{Data}[0]{Name}.": ".$xmldata->{EventData}{Data}[0]{content};
                    $pwrdata .= "\t".$xmldata->{EventData}{Data}[1]{Name}.": ".$xmldata->{EventData}{Data}[1]{content};
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }  
#-----SYSTEM-----------------------------------------------------------------------------            
            #System
            if ($xmldata->{System}{EventID}{content} eq "7045" ) {
                if ($xmldata->{System}{Channel} eq "System") {
                    $outline .= "'".$xmldata->{System}{EventID}{content}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "'".$xmldata->{System}{Security}{UserID}."'|";
                    #$outline .= "'".$xmldata->{UserData}{EventXML}{User}."'|";
                    #$outline .= "'From: ".$xmldata->{UserData}{EventXML}{Address}."'|";
                    #my $pwrdata = lc($xmldata->{EventData}{Data}[0]{content});
                    my $pwrdata = $xmldata->{EventData}{Data}[0]{Name}.": ".$xmldata->{EventData}{Data}[0]{content};
                    $pwrdata .= "\t".$xmldata->{EventData}{Data}[1]{Name}.": ".$xmldata->{EventData}{Data}[1]{content};
                    $pwrdata .= "\t".$xmldata->{EventData}{Data}[2]{Name}.": ".$xmldata->{EventData}{Data}[2]{content};
                    $pwrdata .= "\t".$xmldata->{EventData}{Data}[3]{Name}.": ".$xmldata->{EventData}{Data}[3]{content};
                    eval {
                        $pwrdata .= "\t".$xmldata->{EventData}{Data}[4]{Name}.": ".$xmldata->{EventData}{Data}[4]{content};                    
                    };
					#if (lc($xmldata->{EventData}{Data}[2]{content}) =~/base64/) || (lc($xmldata->{EventData}{Data}[2]{content}) =~ /enc/ ) {
					if ($pwrdata  =~/base64/ || $pwrdata  =~/enc/) {
					    $outline .= "'Y'|";
					  } else {
					    $outline .= "'N'|";
					}
					#my $sb = $xmldata->{EventData}{Data}[0]{content};
					$pwrdata =~ s/\R/     /g;
                    #$outline .= "'".$xmldata->{EventData}{Data}[2]{content}."'|"; #Scriptblock
                    $outline .= "'".$pwrdata."'|"; #Scriptblock
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #Source file
                    $outline .= $inputfile."'";
                    $outline .= "\n";	
		            print $OUT $outline;    
                }
            }  
#-----Security-----------------------------------------------------------------------------               
            #Security
            #Need an example log related to powershell
            if ($xmldata->{System}{EventID} eq "4688" ) {
                if ($xmldata->{System}{Channel} eq "Security") {
                    $outline .= "'".$xmldata->{System}{EventID}."'|";  
                    $outline .= "'".$xmldata->{System}{Computer}."'|";
                    $outline .= "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
                    $outline .= "''|"; #Security userid
                    # 6 TargetDomainname
                    # 5 TargetUserName
                    # 4 TargetUserSid
                    # 8 Logon Type
                    # 11 Workstation Name
                    # 18 IPaddress
                    # 19 Port
                    #$outline .= "'".$xmldata->{EventData}{Data}[6]{content}."\\"
                    #            .$xmldata->{EventData}{Data}[5]{content}." ("
                    #            .$xmldata->{EventData}{Data}[4]{content}.")"."'|";
                    #$outline .= "'".$xmldata->{EventData}{Data}[18]{content}
                    #            .":".$xmldata->{EventData}{Data}[19]{content}
                    #            ."->".$xmldata->{EventData}{Data}[11]{content}
                    #            ."'|"; #address
                    #$outline .= "'Logon Type: ".$xmldata->{EventData}{Data}[8]{content}."'|"; 
                    #$outline .= "'".$eventid{$xmldata->{System}{EventID}}."'|";
                    #$outline .= "'".$xmldata->{System}{Channel}."'|";
                    #$outline .= "'".$inputfile."'";
                    $outline .= $xmldata->{EventData}{Data}[0]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[1]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[2]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[3]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[4]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[5]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[6]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[7]{content}."   ";
                    $outline .= $xmldata->{EventData}{Data}[8]{content}."   ";
                    $outline .= "\n";
		            print $OUT $outline;  
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
    $savedirconfig=$Config->{powershellevtx}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $thread=$Config->{powershellvtx}->{thread};
    $savefilename=$Config->{powershellevtx}->{savefilename};
    $threadapp=$Config->{powershellevtx}->{thread};
    $maxthread=$Config->{powershellevtx}->{maxthread};
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
print "Saving EVTX output file to: $savedir\n";
print "Config File Used: $config\n";
#print "Note: This plugin will recreate the directory structure in the save directory for any processed file.\n";
#chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

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
#find({ wanted => \&threadprocess, follow => 1}, $mntdrive);
print "\tFound: $flcnt\n";
print "Processing Files....\n";
threadprocess2;
#close($fh);


__END__

=head1 pwrshell_etvx_parse.pl

Image device

=head1 SYNOPSIS

pwr_etvx_parse.pl [options] [file ...]

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

B<wpwr_etvx_parse.pl> parse out the events for multiple evtx logs for powershell artifacts.
=cut
