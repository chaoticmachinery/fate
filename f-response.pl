#!/usr/bin/perl

#=============================================================================================
#
#  IR F-Response Gathering Script
#
# Written By: Keven Murphy (RSA)
#
# ./f-response.pl --mac {mac address of interface} --ip {IP address of remote machine to connect to}
#
# Description: Connects out to f-response target and does:
#	* Discovers Drives
#	* Gathers MFT
#	* Gathers Registry and Event Logs
#	* Gathers Misc. directory
#	* Gathers Prefetch directory
#	* Gathers Tasks
#
# Note: You may get errors like the one below. This is perl script has no intelligence. Hence it will
#       try to copy directory paths that do not exist.
#  sh: line 0: cd: /mnt/partition_sdd5/WINDOWS/Temp: No such file or directory
#  tar: HI: Cannot stat: No such file or directory
#  tar: Exiting with failure status due to previous errors
#
# Make sure you have a plugins.good directory for FATE with fls.pl in it. Otherwise this will
# FAIL getting FLS details for non-ntfs filesystems.
#
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
#use IO::Socket;
use Socket;


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
# Read in config file
#=============================================================================================
$Config = Config::Tiny->read( $config );

if ($config eq ""){
  ($filename, $directories, $suffix) = fileparse(abs_path($0));
  $config = $directories."config.ini";
}

my $Config = Config::Tiny->read( $config );
if (defined $config) {
    $analyzemft=$Config->{thirdpartytools}->{analyzemft};
    $siftloc=$Config->{thirdpartytools}->{siftloc};
    $tzworkspf=$Config->{thirdpartytools}->{tzworkspf};
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================



#=============================================================================================
# Init  variables
#=============================================================================================
@devlist = ();
@iscsilist = ();
$iscsicnt = 0;
$devcnt = -1;
$partitionscnt = -1;
@partitions = ();
$waitperiod = 120;  #Max wait time for operations in seconds
$mountother = 0;
$partitioncnt = 0;
$mountdir = "/mnt/partition";
$config = "";
$version="0.4";
print "F-Response -- Version: $version\n";

print "Getting Hostname...";
$host = hostname;
chomp($host);
if ($host =~ /SIFT/) {
    $sift = $siftloc;
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

#=============================================================================================
# Setup environment to begin work
#=============================================================================================
sub getname {
   my $remote_hostname = gethostbyaddr(inet_aton($ip), AF_INET);
   return($remote_hostname);
}
#=============================================================================================


#===================================================================================================
# Create the Save Directory
#===================================================================================================
sub mkdirsavedir {
	my ($savedir) = @_;

	mkdir($savedir);  # || die "Man down!!!!: $savedir $!";
	chdir($savedir);         
	print "   Save DIR: $savedir\n";
}
#===================================================================================================

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
	print "CMD: mount -t ntfs-3g -o ro,nodev,noatime,show_sys_files,streams_interface=windows  /dev/$devpartition $tempmountdir\n";
	print "$error\n";
	if ($error =~ /NTFS signature/) {
	    $mountother++;
	    mountfat($devpartition);
	}
}
#=================================================================================================== 
	
#===================================================================================================
# Mounting partition to ignore_case
#===================================================================================================
sub mount_lowercase {
        my ($devpartition) = @_;
        
	chdir($dircwd);
	print "\nUmounting filesystem so that it can be mounted with ignore_case.\n";
	$error = `umount $tempmountdir`;
	print "\nMounting it ($devpartition) to ignore case...\n";
	if ($sift eq "") {
	     $error = `mount -t lowntfs-3g -o ro,nodev,noatime,ignore_case,show_sys_files  /dev/$devpartition $tempmountdir 2>&1`;
	     print "CMD: mount -t lowntfs-3g -o ro,nodev,noatime,ignore_case,show_sys_files  /dev/$devpartition $tempmountdir\n";	
	   } else {
	     $error = `ntfsmount /dev/$devpartition $tempmountdir -o ro,nodev,noatime,case_insensitive,streams_interface=windows 2>&1`;
	     print "CMD: ntfsmount /dev/$devpartition $tempmountdir -o ro,nodev,noatime,case_insensitive,streams_interface=windows\n";
	}
	print "$error\n";
	if ($error =~ /NTFS signature/) {
	    mountfat($devpartition);
	}	
}
#=================================================================================================== 
	
#===================================================================================================
# MFT
#===================================================================================================
sub getMFT {
        my ($devpartition) = @_;
        
	chdir($dircwd);
        print "\nCopying MFT... Please hold. Attempting to connect...\n";
        print "NOTE: Make sure your machine is set to UTC time! Otherwise timestamps will be off as they are parsed by analyzeMFT.\n";
        $mftname = "./mft_raw_disk".$partitioncnt; 
        copy("$tempmountdir/\$MFT","$mftname");
        print "Creating the MFT CSV file... Output saved to: $mftname.csv\n";
        $error=`$sift/$analyzemft -f $mftname -o $mftname.csv`;
        chdir($dircwd);
}
#=================================================================================================== 

#===================================================================================================
# Reg and Logs
#===================================================================================================        
sub getRegLogs {
        my ($devpartition) = @_;
        
        print "\nGetting Registry... AND Getting Logs...\n";
	print "Check Registry to find all Event logs as there may be other locations\n";
	$savedir = $dircwd."registry_".$devpartition;
        
	if (-d "$tempmountdir/WINDOWS") {
	    mkdirsavedir($savedir);
	    $error = `(cd $tempmountdir/WINDOWS/system32; find ./config -maxdepth 2 -type f | tar cf - -T -) | tar xvf -`;
	    print "\tCMD: (cd $tempmountdir/WINDOWS/system32; find ./config -maxdepth 2 -type f | tar cf - -T -) | tar xvf -\n";
	}
	if (-d "$tempmountdir/WINNT") {
	    mkdirsavedir($savedir);  
	    $error = `(cd $tempmountdir/WINNT/system32; find ./config -maxdepth 2 -type f | tar cf - -T -) | tar xvf -`;
	    print "\tCMD: (cd $tempmountdir/WINNT/system32; find ./config -maxdepth 2 -type f | tar cf - -T -) | tar xvf -\n";
	}  
	chdir($dircwd);
}
#=================================================================================================== 
	
#===================================================================================================
# Tasks
#===================================================================================================             
sub getTasks {
        my ($devpartition) = @_;
        
        print "\nGetting tasks...";
	$savedir = $dircwd."Tasks_".$devpartition;       
	if (-d "$tempmountdir/WINDOWS") {
	    mkdirsavedir($savedir);  	
	    $error = `(cd $tempmountdir/WINDOWS; tar cf - Tasks) | tar xvf -`;
	    $error = `(cd $tempmountdir/WINDOWS/system32/; tar cf - Tasks) | tar xvf -`;
	}
	if (-d "$tempmountdir/WINNT") {
	    mkdirsavedir($savedir);  	  
	    $error = `(cd $tempmountdir/WINNT; tar cf - Tasks) | tar xvf -`;
	    $error = `(cd $tempmountdir/WINNT/system32/; tar cf - Tasks) | tar xvf -`;
	}         
        #$error = `(cd $tempmountdir/WINDOWS; tar cf - Tasks) | tar xvf -`;
        #$error = `(cd $tempmountdir/WINDOWS/system32/; tar cf - Tasks) | tar xvf -`;
	print "Extracting job information... Saving it to: jobparser.log\n";
	$error = `$sift/appl/ir.work/jobparser.py -d Tasks/ > jobparser.log`;
	chdir($dircwd);
}
#=================================================================================================== 
	
#===================================================================================================
# Prefetch
#===================================================================================================     
sub getPrefetch {
        my ($devpartition) = @_;
        
        print "\nGathering Prefetch";
	$savedir = $dircwd."Prefetch_".$devpartition;      
	if (-d "$tempmountdir/WINDOWS") {
	    mkdirsavedir($savedir);  	
	    $error = `(cd $tempmountdir/WINDOWS; tar cf - Prefetch) | tar xvf -`;
	}
	if (-d "$tempmountdir/WINNT") {
	    mkdirsavedir($savedir);  	  
	    $error = `(cd $tempmountdir/WINNT; tar cf - Prefetch) | tar xvf -`;
	}        
	chdir($dircwd); 
	print "Processing Prefetch... Saving to: $savedir.csv\n";
	print "Note: Needs to be ran twice to handle XP and Vista+ boxes\n";
	if ($host =~ /SIFT/) { 
	    $error = `/usr/local/bin/pref.pl -c -v -d $savedir >> $savedir.csv`;
	    $error = `/usr/local/bin/pref.pl -c -d $savedir >> $savedir.csv`;
	  } else {
	    $error = `/export/appl/evt/pref.pl -c -v -d $savedir >> $savedir.csv`;          
	    $error = `/export/appl/evt/pref.pl -c -d $savedir >> $savedir.csv`;
	}
}
#===================================================================================================  

#=============================================================================================

GetOptions ("mac=s"   => \$mac,      #MAC address of interface
	    "ip=s"    => \$ip	     #IP
           ) ||  pod2usage(-verbose => 0);

    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory args '--ip' or '--mac' is missing}
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
print "Working Directory is: $dircwd\n\n"; 
mkdir($dircwd);

print "Connecting to remote host: $ip\n";
$remote_hostname = getname();
print "The remote hostname (DNS lookup) is: $remote_hostname\n";

my $error = `iscsiadm -m iface -I iface0 --op=new`; 
print "ISCSI CMD: iscsiadm -m iface -I iface0 --op=new\n";
$error = `iscsiadm -m iface -I iface0 --op=update -n iface.hwaddress -v $mac`; 
print "ISCSI CMD: iscsiadm -m iface -I iface0 --op=update -n iface.hwaddress -v $mac\n";


getdevices();

# Need to do just one partition
# Do: 
# 0) Comment out the line above with: getdevices();
# 1) ls -al /dev/sd*
# 2) iscsiadm -m discovery -t st -p {ip}
# 3) Log into the  iscsiadm -m node -T  {drive or vol} -l
# 4) ls -al /dev/sd*
# 5) Find new device
# 6) Alter lines below as needed
#$partitions[0]="sdg";
#$partitions[1]="sdh1";
#$partitions[2]="sdh2";


foreach my $devpartition (@partitions) { 
    
        $mountother = 0;
	#Creating the save directory
	$tempmountdir = $mountdir;
	$tempmountdir .= "_".$devpartition;
	print "Creating Directory for mounting: $tempmountdir\n";
	unless(-e $tempmountdir or mkdir $tempmountdir) {
	    die "Unable to create $tempmountdir\n";
	}    
	$devlist[$partitioncnt] = $devpartition;
	$partitioncnt++;

	#Disable/Enable these as necessary
	mount_full($devpartition);
	if ($mountother > 0) {
	    print "WARNING: Filesystem is not NTFS.\n";
	    print "\tRunning FATE plugin fls.pl. This may take some time.\n";
	    print "\tOutput will be in the fls directory.\n";
	    $error = `$sift/appl/ir.work/plugins.good/fls.pl --mntdrive $tempmountdir`;
	    my $newname = "fls.".$devpartition;
	    rename("fls",$newname);
	   } else {
	    getMFT($devpartition);
	    mount_lowercase($devpartition);
	}
	getRegLogs($devpartition);
	getTasks($devpartition);
	getPrefetch($devpartition);
	
	print "All done with the partition\n";
	print "==========================================================\n\n";
}

print "Parsing PreFetch... Saving it to: prefetch_pf.log\n";
if ($host =~ /SIFT/) { 
    #Hard coded for SIFT
    $error = `find . -name *.pf -type f | /usr/local/bin/pf -pipe -v -csv > prefetch_pf.log`;
   } else {
    $error = `find . -name *.pf -type f | $tzworkspf -pipe -v -csv > prefetch_pf.log`;
}

chdir($orgpath);

print "\n\nFATE Processing: Registry & Log2Timeline\n";
print "Note: CPU/IO intensive operations.\n";
print "FATE Output: $orgpath\n";
$error = `$sift/appl/ir.work/process_thread.pl --mntdrive $workdata`;

print "\n\n\nComplete with all tasks.\n\n";

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
print OUT "iscsiadm -m discovery --portal \"$ip:3260\" --op=delete\n";

my $chmodfile = $orgpath."umountcmd.sh";
print "Saved commands umount commands to: $chmodfile\n";
print "To run: $chmodfile\n";
close(OUT);

chmod 0755, "$chmodfile";

close(ISCI);
