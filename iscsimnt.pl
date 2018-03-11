#!/usr/bin/perl

#=============================================================================================
#
#  IR F-Reponse Gathering Script
#
# Written By: Keven Murphy (RSA)
#
# ./iscsimnt.pl --mac {mac address of interface} --ip {IP address of remote machine to connect to}
#
# Desciption: Makes mounting iscsi drives easier. 
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


$version="0.2";
print "ISCSI Mount -- Version: $version\n\n";

#=============================================================================================
# Inital variables
#=============================================================================================
@devlist = ();
@iscsilist = ();
$iscsicnt = 0;
$devcnt = -1;
$partitionscnt = -1;
@partitions = ();

$partitioncnt = 0;
$mountdir = "/mnt/partition";


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

#print "Getting MAC address of your default interface...\n";
#$default_interface = `route | grep default | awk -F\" \" \'{print \$NF}\'`;
#$mac = `ip addr | grep -A5 $default_interface | grep ether`;# | cut -d\"\/\" -f2- | cut -d\" \" -f2 | head -n1;
#print "Default Interface: $default_interface\n";
#print "MAC Address: $mac\n";


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
# GetDevices
#=============================================================================================
sub getdevices {

    my $diskcnt = -1;
    my $currentportal = 0;
    open (ISCI, "iscsiadm -m discovery -t st -p $ip -P1 | grep disk | cut -d: -f2- | cut -d\' \' -f2- |");

    print "ISCSI CMD: iscsiadm -m discovery -t st -p $ip -P1 | grep disk | cut -d: -f2- | cut -d\' \' -f2- |\n";
    while (my $line = <ISCI>) {
	chomp($line);
	$iscsilist[$iscsicnt] = $line;
	$iscsicnt++;
	
        print "ISCSI CMD: iscsiadm -m node -T $line -l\n";
        $error = `iscsiadm -m node -T $line -l`;
        $diskcnt++;
    }
    
	#----------------------------------------------------------------------------------
	# Get the list of partitions
	#----------------------------------------------------------------------------------
	while ($devcnt < $diskcnt) {
	    #open (LISTDEV, "iscsiadm -m session --print 3 | grep \"Attached scsi disk\" |");
	    
	    $currentportal = 0;
	    open (LISTDEV, "iscsiadm -m session --print 3 |");
	    while (my $listline = <LISTDEV>) {
	      #print "Line: $listline";
	      chomp($listline);
	      if ($listline =~ /Current Portal/) {
	          if ($listline =~ /$ip/) {
	              $currentportal++;
	              #print "Found our IP: $ip\n";
		  }
	      }
	      if ($listline =~ /Attached scsi disk/) {
		  if ($currentportal > 0) {
		      @devicelist = split(/\s+/,$listline);
		      if ($devicelist[4] ~~ @devlist) { 
			} else {
			  $devcnt++;
			  $devlist[$devcnt]=$devicelist[4];
			  $currentportal = 0;
		      }
		  }
	      }
	    }
	    close(LISTDEV);
	    #print "$devicelist[4] Devcnt: $devcnt = $diskcnt\n";
	}
	
	print "Devices: @devlist\n";
	print "Note: If this hangs, then you have not logged out of previous sessions.\n";
        print "\tFix: Cntrl-C and do a iscsiadm -m node -u\n";

	my $lsoutput = "";
	foreach my $drv (@devlist) {
	  my $dircontinue = -1;
	  my $seccnt = 0;
	  my $partition_error = 0;
	  while ($dircontinue < 0) {
	    $lsoutput = `ls /dev/$drv? 2>&1`;
	    sleep(1);
	    if ($lsoutput =~ /cannot access/) {
		} else {
		  $dircontinue++;
	    }
	    if ($seccnt > $waitperiod) {
	        print "\tNOTICE: Found an issue with $drv. Moving on to next device.\n";
	        $partition_error++;
		$dircontinue++;  #if it takes longer than X seconds then there is an issue. Move on to the next device.
	    }
	    $seccnt++;
	  }
	  if ($partition_error == 0) {
	      my (@partlist) = split(/\s+/,$lsoutput);
	      chomp(@partlist);
	      my $remove = "\/dev\/";
	      map { s/$remove//g; } @partlist;
	      my %k;
	      map { $k{$_} = 1} @partitions;
	      push(@partitions, grep { !exists $k{$_}} @partlist);
	  }
	}
	print "Partitions: @partitions\n";
    
    close(ISCI);
}
#=============================================================================================


#===================================================================================================
# Mount Dir as FAT
#===================================================================================================
sub mountfat {
	my ($devpartition) = @_;

        print "\nNOTICE: Mounting it ($devpartition) using \"mount -t auto\" because filesystem is not NTFS.\n";
	$error = `mount -t auto -o ro,tz=UTC  /dev/$devpartition $tempmountdir`;
	print "CMD: mount -t auto -o ro,tz=UTC  /dev/$devpartition $tempmountdir\n";
	print "$error\n";
}
#===================================================================================================

#===================================================================================================
# Mounting partition
#===================================================================================================
sub mount_full {
        my ($devpartition) = @_;
        
        print "\nMounting it ($devpartition) right away, G\'vernor\n";
	$error = `mount -t ntfs-3g -o ro,nodev,noatime,show_sys_files,streams_interface=windows  /dev/$devpartition $tempmountdir 2>&1`;
	print "CMD: mount -t ntfs-3g -o ro,nodev,noatime,ignore_case,show_sys_files,streams_interface=windows  /dev/$devpartition $tempmountdir\n";
	print "$error\n";
	if ($error =~ /NTFS signature/) {
	    $mountother++;
	    mountfat($devpartition);
	}
}
#=================================================================================================== 





#=============================================================================================

GetOptions ("mac=s"   => \$mac,      #MAC address of interface
	    "ip=s"    => \$ip	     #IP
           ) ||  pod2usage(-verbose => 0);

    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory arguement'--ip' is missing}
                 -exitval => 1,
                 -verbose => 1 }
        ) unless ($mac,$ip);
        
        
        
#=============================================================================================
# Setup environment to begin work
#=============================================================================================
$dircwd = getcwd();
chomp($dircwd);
$dircwd = addslash($dircwd);
$workdata = "drives";
$orgpath = $dircwd;
$dircwd .= $workdata;
$dircwd = addslash($dircwd);
#print "Working Directory is: $dircwd\n\n"; 
#mkdir($dircwd);
        
my $error = `iscsiadm -m iface -I iface0 --op=new`; 
print "ISCSI CMD: iscsiadm -m iface -I iface0 --op=new\n";
$error = `iscsiadm -m iface -I iface0 --op=update -n iface.hwaddress -v $mac`; 
print "ISCSI CMD: iscsiadm -m iface -I iface0 --op=update -n iface.hwaddress -v $mac\n";

getdevices();



    
foreach my $devpartition (@partitions) { 

    #Creating the save directory
    $tempmountdir = $mountdir;
    $tempmountdir .= "_".$devpartition;
    print "Creating Directory for mounting: $tempmountdir\n";
    unless(-e $tempmountdir or mkdir $tempmountdir) {
	die "Unable to create $tempmountdir\n";
    }    
    $devlist[$partitioncnt] = $devpartition;
    $partitioncnt++;

    mount_full($devpartition);
#    if ($mountother > 0) {
#	} else {
#	mount_lowercase($devpartition);
#    }
}
chdir($orgpath);

# Creates a script to umount drives
open (OUT, "> $orgpath/umountcmd.sh");
if ($host =~ /SIFT/) {
    print OUT "#!/bin/bash\n";
  } else {
    print OUT "#!/usr/bin/bash\n";
}


print "\n\nTo umount and logout of iscsi do the following:\n";
foreach $mnt (@devlist) {
  print "umount /dev/$mnt\n"; 
  print OUT "umount /dev/$mnt\n";
}
#print " iscsiadm -m node -T  iqn.2008-02.com.f-response.sgsingvtestrt01:disk-1 -u";
foreach $mnt (@iscsilist) {
  print "iscsiadm -m node -T $mnt -u\n"; 
  print OUT "iscsiadm -m node -T $mnt -u\n";
}

my $chmodfile = $orgpath."umountcmd.sh";
print "Saved commands umount commands to: $chmodfile\n";
print "To run: $chmodfile\n";
close(OUT);

chmod 0755, "$chmodfile";

close(ISCI);
