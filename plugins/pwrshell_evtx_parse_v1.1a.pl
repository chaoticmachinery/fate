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
#use Parse::Evtx;
#use Parse::Evtx::Chunk;
use Carp::Assert;
use IO::File 1.14;
#use XML::Simple;
use Pod::Usage;
use Config::Tiny;
use File::Path;
use File::Path qw(make_path);
use Cwd 'abs_path';
use Cwd;
use File::Find;
use File::Copy;
use File::Basename;
use threads;
use threads::shared;
use Thread::Queue;


# Used for testing
#use Data::Dumper;
#use  Data::Dumper::Perltidy;

my $version = "1.6";
my $inputfile = "";
my $opt_help = "";
my $opt_man = ""; 
my @fileslist;
my $flcnt = 0;
my $process_q = Thread::Queue -> new();

my %eventid =  ( 
    #Microsoft-Windows-Powersell%4Operational.evtx (Dst Host)
    '400'   => 'Start of any local or remote PowerShell activity',
    '403'   => 'End of PowerShell activity',
    '600'   => 'Onset of PowerShell remoting activity on both src and dest systems',
    '4104'  => 'Scriptblock text',
	#System.evtx  (Dst Host)
	'7040' => 'Recorded when PowerShell remoting is enabled',
    '7030' => '',
    '7045' => '',
    #WinRM
    '169'  => 'Authenication prior to PowerShell remoting on a accessed system',
    #Security
    '4688' => 'Indicates the execution of PowerShell console or interpreter',
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

#=============================================================================================
# Process the files
#=============================================================================================
sub threadprocess2 {

    my $cnt = 0;
    my $left = 0;
    my $pausecnt = 0;

    
    foreach $evtxfile (@filelist) {
      $process_q -> enqueue ( $evtxfile );
    }
    $process_q -> end();
    
    print "Processing queued files...\n";
    for (0..$maxthread) {
       threads -> create ( \&worker );
    }
    
    my @threadlist = threads->list(threads::running);
    my $num_threads = $#threadlist;
    print "Waiting for $num_threads threads to complete processing files...\n";
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
      print "Waiting for $num_threads threads to complete processing files...\n";
    }

}

sub worker {

  while ( my $evtxfileworker = $process_q -> dequeue() )
  {
    chomp ( $evtxfileworker );
    print "\tThread " .threads -> self() -> tid(). ": Reviewing $evtxfileworker\n";
    
    eval {
       rdpevtx($evtxfileworker);
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
	 #print"FILE: $File::Find::name \n";
     if(lstat $_ and not stat $_) {
        print "\tBad Symbloic Link: $File::Find::name\n";
        return;
     }
	 if (-d) {
		 return;
	 }
    # open(FILE, $_) or die("Error reading file $File::Find::name, stopped: $!");
    # read(FILE, $type, 7);
    # close(FILE);
    # if ($type eq "ElfFile") {
	   $filelist[$flcnt] = $File::Find::name;
	   $flcnt++;
	   #rdpevtx($_);
     #}
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
    return($goodfile);
}
    
sub rdpevtx {
    my ($inputfile) = @_;
    my $goodfile = 0;
      
    
    my $test = `$evtxparser -i "$inputfile" -o "$savedir"`;
    
    return();

}

#=============================================================================================

GetOptions ("mntdrive=s"   => \$mntdrive, # output directory
            "help"         => $opt_help,
			"man"          => $opt_man,
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
    $savedirconfig=$Config->{pwrshellevtx}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $thread=$Config->{pwrshellevtx}->{thread};
    $savefilename=$Config->{pwrshellevtx}->{savefilename};
    $threadapp=$Config->{pwrshellevtx}->{thread};
    $maxthread=$Config->{pwrshellevtx}->{maxthread};
    $evtxparser=$Config->{pwrshellevtx}->{evtxparser};
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
print "Saving PWRSHELLEVTX output file to: $savedir\n";
print "Config File Used: $config\n";
print "Note: This plugin will recreate the directory structure in the save directory for any processed file.\n";
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
#open(my $fh, '>', $sfilename) or die "Could not open file '$sfilename' $!";
#print $fh header2;
#close($fh);

#Find the EVTX
print "Searchng for EVTX files.\n";
#my $lastchar = substr($mntdrive, -3);
#print "LC: $lastchar\n";
#while ($lastchar eq "\\") {
#	print "MNTDRIVE: $mntdrive\m";
#	chop($mntdrive);
#	$lastchar = substr($mntdrive, -1);
#}
find(\&process, $mntdrive);	
#find({ wanted => \&threadprocess, follow => 1}, $mntdrive);
print "\tFound: $flcnt\n";
print "Processing Files....\n";
threadprocess2;
#close($fh);


__END__

=head1 NAME

pwrshellevtx_etvx_parse.pl

=head1 SYNOPSIS

pwrshellevtx_evtx_parse.pl [options] [file ...]

Options:

--mntdrive {directory}   Directory where the EVTX files are (MANDATORY)

--help       Brief help message

--man        Full documentation

=head1 OPTIONS

=over 8

=item B<--mntdrive> {directory}

	{directory} = The directory or directories full of evtx log files.
	
	If there are spaces in the directory name please use "" around the entire path. For example: "E:\\EVTXlogs\\"
	
	Windows Recommendations:
    1) Always use \\ for path seperators. 

=back

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<wpwrshellevtx_etvx_parse.pl> parse out the events for multiple evtx logs for powershell artifacts.

=cut
