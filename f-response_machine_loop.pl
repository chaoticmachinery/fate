#!/usr/bin/perl


#=============================================================================================
#
# Automated IR F-Reponse Gathering Script
#
# Written By: Keven Murphy (RSA)
#
# ./f-response_machine_loop.pl 
#
# Desciption: Script will automate the collection of data from a list of hosts (ips.txt).
#
# ips.txt Details:
# * Make sure that it is one IP address per line.
# * Be sure to run dos2unix on any file coming from Windows!
#=============================================================================================

use File::Find;
use File::Copy;
use File::Basename;
use Digest::MD5 qw(md5_hex);
use Cwd 'abs_path';
use Cwd;
use Switch;
use Getopt::Long;
use Config::Tiny;
use File::Path;
use Pod::Usage;
use Sys::Hostname;

$version = "0.1";

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
# Setup environment to begin work
#=============================================================================================
$orgpath = getcwd();
chomp($orgpath);
$orgpath = addslash($orgpath);
$version="0.1"; 
$mac = "00:00:00:00:00:00";   #Need the mac address of from the machine
$ir_work = "/appl/ir.work/f-response.pl";


GetOptions ("ip=s"    => \$ip	     #IP
           ) ||  pod2usage(-verbose => 0);

    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory args '--ip' is missing}
                 -exitval => 1,
                 -verbose => 1 }
        ) unless ($ip);


print "Getting Hostname...";
$host = hostname;
chomp($host);
if ($host =~ /SIFT/) {
    $sift = "/home/sansforensics/Desktop";
    print "\tIdentified system as SIFT\n";
  } else {
    $sift = "";
    print "\tIdentified system as $host\n";
}

print "Identifying the default interface...\n";
print "Note: This may hang for a bit if your network isn\'t configured correctly.\n";
my $temp = `route | grep default`;
my (@tmparray) = split(/\s+/,$temp);
my $interface = $tmparray[7];
@tmparray=();
print "\tDefault Interface: $interface\n\n";
print "Getting MAC address for default interface...\n";
$temp = `ifconfig $interface | grep ether`;
@tmparray = split(/\s+/,$temp);
my $mac = $tmparray[2];
print "\tDefault interface MAC address: $mac\n\n";
@tmparray=();

#=============================================================================================

print "Automated F-Response -- Version: $version\n\n";

print "Logging out of ALL iscsi mounts\n";
open (MNTS, "cat /etc/mtab | grep partition_sd |");
while (my $mntline = <MNTS>) {
  my @mntfields = split(' ', $mntline);
  print "\tUmounting $mntfields[1]\n";
  $error = `umount $mntfields[1]`;
}
close(MNTS);

print "Logging out of ALL iscsi connections\n";
$error = `iscsiadm -m node --logout all`;
print "CMD: iscsiadm -m node --logout all\n";




open (FILE, "< ./ips.txt") or die "Cannot read ips.txt: $!";

while (my $ip = <FILE>) {
    chdir($orgpath);
    chomp($ip);
    my $firstchar = substr $ip, 0, 1;
    if ($firstchar ne "#") {
	print "\n\nWorking on IP: $ip\n";

	#=============================================================================================
	# Create our work directory
	#=============================================================================================
	$dircwd = $orgpath;
	$dircwd .= $ip;
	$dircwd = addslash($dircwd);
	print "Working Directory is: $dircwd\n\n"; 
	mkdir($dircwd);
	chdir($dircwd); #change to our work directory
	
	#=============================================================================================
	# Staring ir_work.pl
	#=============================================================================================        
	print "CMD: $ir_work --mac $mac --ip $ip\n";
	my $log = $dircwd.$ip."_ir_work.log";
	$error = `$ir_work --mac $mac --ip $ip | tee $log`;
	$error = `./umountcmd.sh`; # need to umount
    }
}

chdir($orgpath);
close(FILE);
