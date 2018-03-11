#!/usr/bin/perl

use Config::Tiny;
use Getopt::Long;
use Pod::Usage; 
use File::Basename;
use Cwd 'abs_path';
use Cwd;
use Switch;
use File::Find;

$version = 0.2;
print "Automounter: $version\n\n";

$found = 0;
my @mmlsfiles = ();
my @encasefiles = ();
my @ddfiles = ();

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
# Encase Check
#=============================================================================================
sub encasecheck {
    my ($ddfile,$drivepath) = @_;
    my $OEMbegin = 0;
    my $OEMlen = 3;
    my $OEM = ""; 
    
    print "Checking for Encase...\n";
    #print "\tPartition Start: $calpartitionstart";
    print "\tReading in 512 bytes\n";
    
    open (INFILE, "<:raw", $ddfile) || die "Can't open input file \"$ddfile\": $!";
    binmode INFILE;
    seek(INFILE, $calpartitionstart, 0);	# Seek out the beginning of the partition
    $i = 0;
    while (not (eof INFILE) && $i < 512) {
	read (INFILE,$byte,1);
	$boot[$i] = unpack ("C", $byte);
	$i++;
    }  
    close(INFILE);
    for (my $cnt = $OEMbegin; $cnt < $OEMbegin+$OEMlen; $cnt++) {
	$OEM .= chr($boot[$cnt]);
    }
    if ($OEM eq "EVF") {
	print "\tEncase detected\n";
	createdir($ewfdir);
        my $EVFmountout = `$ewfmount \"$ddfile\" ./$ewfdir`;   
	
	if ($mmlsfiles[0] eq "") {
	   print "Generating MMLS file called: $ddfile.mmls\n";
	   my $mmlsfilename = $ddfile.".mmls";
	   my $mmlsout = `$sleuthkitdir/mmls ./$ewfdir/ewf1 > \"$mmlsfilename\" `;
	   print "\tCMD: $sleuthkitdir/mmls ./$ewfdir/ewf1  > \"$mmlsfilename\" \n";
	   
	   my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($mmlsfilename);
 
	   if ($size < 1) {
	   #if (-s "\"$ddfile.mmls\"") {
	   #if ($mmlsout =~ /Cannot determine partition type/) {
	      #} else {
	        print "\tThe ./$ewfdir/ewf1 appears to be a partition.\n";
	        print "\tRunning a file on the partition and saving it as $ddfile.mmls\n";
	        $mmlsout = `echo \"Meta !-- ignore this line  --!\" > \"$ddfile.mmls\"`;
	        $mmlsout = `file ./$ewfdir/ewf1 >> \"$ddfile.mmls\"`;
	        #print "file ./$ewfdir/ewf1 > \"$ddfile.mmls\"\n";
	        #print "MMLS: $mmlsout\n";
	      } else {
	   }
	   $ddfiles[0] = "$ewfdir/ewf1";
	}
    }

    #return($path);
}
#=============================================================================================

#=============================================================================================
# Encryption Check
#=============================================================================================
sub encryptcheck {
    my ($calpartitionstart,$ddfile,$drivepath,$password) = @_;
    my $OEMbegin = 3;
    my $OEMlen = 8;
    my $OEM = ""; 
    
    print "Checking for Encryption...\n";
    print "\tPartition Start: $calpartitionstart";
    print "\tReading in 512 bytes\n";
    
    open (INFILE, "<:raw", $ddfile) || die "Can't open input file \"$ddfile\": $!";
    binmode INFILE;
    seek(INFILE, $calpartitionstart, 0);	# Seek out the beginning of the partition
    $i = 0;
    while (not (eof INFILE) && $i < 512) {
	read (INFILE,$byte,1);
	$boot[$i] = unpack ("C", $byte);
	$i++;
    }  
    close(INFILE);
    for (my $cnt = $OEMbegin; $cnt < $OEMbegin+$OEMlen; $cnt++) {
	$OEM .= chr($boot[$cnt]);
    }
    if ($OEM eq "-FVE-FS-") {
	print "\tBitlocker encryption detected\n";
        print "\tMounting partition\n";
	my $offset = $calpartitionstart;
	my $bderawpath = $drivepath . "_bderaw";
	if (-d $bderawpath) {
	  } else {
		mkdir($bderawpath, 0700) || die ("Cannot make $bderawpath directory");
		print "\tCreating BDE raw directory: $bderawpath\n";
	}
	my $bdemount = "bdemount -o $offset  -r $password $ddfile $bderawpath";
	my $errorstatus = system($bdemount);
	my $mntcmd = "mount -t ntfs-3g -o loop,ro,nodev,noatime,show_sys_files,streams_interface=windows $bderawpath/bde1 $drivepath";
	my $errorstatus = system($mntcmd);
    }

    #return($path);
}
#=============================================================================================

#=============================================================================================
# getpartitionstart
#=============================================================================================
sub getpartitionstart {
    my ($getpartionstart) = @_;

    my $calpartitionstart = 0;
    
    if ($getpartionstart =~ /ewf/) {
	$calpartitionstart = 0;   #setting offset to 0
      } else {
	#print "$line\n";
	$getpartionstart =~ s/\h+/ /g;
	#print "$line\n";
	@fields = split(/\h/, $getpartionstart);
	#print "$fields[2]\n";
	$fields[2]=~s/^[0]*//;
	#print "$fields[2]\n";
	$calpartitionstart = $fields[2] * 512;
    }
    return($calpartitionstart);
}
#=============================================================================================

#=============================================================================================
# findsystem32
#=============================================================================================
sub process {
    my ($getpartionstart) = @_;

    #my $found = 0;
    
    $srchfilename = lc($_);
    #print "$srchfilename\n";
    if ($srchfilename =~ /sam/) {
      my $dir = lc($File::Find::dir);
      if ($dir =~ /system32\/config/) {
	  $found++;
      }
    }
}
#=============================================================================================

#=============================================================================================
# findsystem32
#=============================================================================================
sub createdir {
    my ($drvmntpath) = @_;
    if (-d $drvmntpath) {
	    print "\tMount path $drvmntpath exists.\n";
      } else {
	    mkdir($drvmntpath, 0700) || die ("Cannot make $drvmntpath directory");
	    print "\tCreating mount directory: $drvmntpath\n";
    }
}
#=============================================================================================

#=============================================================================================
# Get MMLS info
#=============================================================================================
sub mmlsinfo {
    opendir my($dirhandle),$outdir  or die "Couldn't open dir '$outdir': $!";
    @mmlsfiles = grep { /^*.mmls$/ } readdir $dirhandle;
    closedir($dirhandle);
}
#=============================================================================================

#=============================================================================================
# Check for Encase file
#=============================================================================================
sub chkencasefile {
    opendir my($dirhandle),$outdir  or die "Couldn't open dir '$outdir': $!";
    @encasefiles = grep { /^*.E01$/ } readdir $dirhandle;
    closedir($dirhandle);
    if ($encasefiles[0]) {
      encasecheck($outdir.$encasefiles[0],$drivepath);
    }
}
#=============================================================================================

#=============================================================================================
# Check for dd file
#=============================================================================================
sub chkddfile {
    opendir my($dirhandle),$outdir  or die "Couldn't open dir '$outdir': $!";
    @ddfiles = grep { /^*.dd$/ } readdir $dirhandle;
    closedir($dirhandle);
}
#=============================================================================================


GetOptions ("outdir=s"   => \$outdir,      	# output directory
            "passwd=s"   => \$password		#Password to mount encrypted partitions
           ) ||  pod2usage(-verbose => 0);
		      
    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
#    pod2usage( { -message => q{Mandatory arguement '--outdir' is missing}
#		 -exitval => 1,
#		 -verbose => 1 }
#	) unless ();

#=============================================================================================
# Read in config file
#=============================================================================================
$Config = Config::Tiny->read( $config );

if ($config eq ""){
  my($filename, $directories, $suffix) = fileparse(abs_path($0));
  $config = $directories."config.ini";
}

my $Config = Config::Tiny->read( $config );
if (defined $config) {
    $mntpath=$Config->{mntpath}->{mntpath};
    $emailto=$Config->{email}->{to};
    $emailfrom=$Config->{email}->{from};
    $ewfmount=$Config->{mntoptions}->{ewfmount};
    $ewfdir=$Config->{mntoptions}->{ewfdir};    
    $sleuthkitdir=$Config->{sleuthkit}->{sleuthkitdir};
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================

#=============================================================================================
# Outdir not given
#=============================================================================================
if ($outdir eq "") {
  $outdir = getcwd();
  print "--outdir={path} not given.\nUsing PWD for --outdir option: $outdir\n";
}
#=============================================================================================

$outdir = addslash($outdir);
#$mntpath = addslash($mntpath);
$drvmntpath = $outdir.$mntpath;

print "\n\nUsing config: $config\n";
print "Mounting partitions at: $drvmntpath\n";
#if (-d $drvmntpath) {
#	print "\tMount path $drvmntpath exists.\n";
#   } else {
#	mkdir($drvmntpath, 0700) || die ("Cannot make $drvmntpath directory");
#	print "\tCreating mount directory: $drvmntpath\n";
#}

chkddfile();
chkencasefile();
mmlsinfo();
#if ($mmlsfiles[0] eq "") {
#    mmlsinfo();
#  } else {
#}

$mmlsfull = $outdir.$mmlsfiles[0];
print "Opening mmls output file: $mmlsfull\n";
open(MMLSFILE, "< $mmlsfull")|| die("Could not open MMLS output file: $mmlsfull!");

print "Searching for Windows %SYSTEMROOT%...\n";
my $tablestart = 0;
my $partitionnum = 0;
while (defined ($line = <MMLSFILE>)) {
  if ($line =~ /Meta/) {
     $tablestart++;
  }
  if ($tablestart > 0) {
    switch ($line) {
	case /FAT16/ {
	  $calpartitionstart = getpartitionstart($line);
	  my $drivepath = $drvmntpath . $partitionnum;
	  createdir($drivepath);
	  $partitionnum++;
	  $mntcmd = "mount -t msdos -o loop,ro,nodev,noatime,offset=$calpartitionstart $outdir$ddfiles[0] $drivepath";
	  print "\tMount CMD: $mntcmd\n";
	  my $errorstatus = system($mntcmd);
	  find(\&process, $drivepath);
	  if ($found > 0) {
	    print "\tFound evidence of Windows %SYSTEMROOT% on partition: $line\n";
	    print "\tMounted at: $drivepath\n";
	    last;
	  }
	}
	case /FAT32/ {
	  $calpartitionstart = getpartitionstart($line);
	  my $drivepath = $drvmntpath . $partitionnum;
	  createdir($drivepath);
	  $partitionnum++;
	  $mntcmd = "mount -t vfat -o loop,ro,nodev,noatime,offset=$calpartitionstart $outdir$ddfiles[0] $drivepath";
	  print "\tMount CMD: $mntcmd\n";
	  my $errorstatus = system($mntcmd);
	  find(\&process, $drivepath);
	  if ($found > 0) {
	    print "\tFound evidence of Windows %SYSTEMROOT% on partition: $line\n";
	    print "\tMounted at: $drivepath\n";
	    last;
	  }  
	}	
	case /NTFS/ {
	   #mount -t ntfs-3g -o loop,ro,nodev,noatime,show_sys_files,streams_interface=windows,offset=`echo $(( $PART * 512 ))`  $DDFILE $MNTPATH
	  $calpartitionstart = getpartitionstart($line);
	  my $drivepath = $drvmntpath . $partitionnum;
	  createdir($drivepath);
	  $partitionnum++;
	  $mntcmd = "mount -t ntfs-3g -o loop,ro,nodev,noatime,show_sys_files,streams_interface=windows,offset=$calpartitionstart $outdir$ddfiles[0] $drivepath";
	  print "\tMount CMD: $mntcmd\n";
	  my $errorstatus = system($mntcmd);
	  #print "ERROR: $errorstatus -- Could not mount partition.\n";
	  if ($errorstatus == 3072) {
	      encryptcheck($calpartitionstart,$outdir.$ddfiles[0],$drivepath,$password);
	  }
	  find(\&process, $drivepath);
	  if ($found > 0) {
	    print "\tFound evidence of Windows %SYSTEMROOT% on partition: $line\n";
	    print "\tMounted at: $drivepath\n";
	    last;
	  }
	}
	else {
	}
    }
  }
}


close(MMLSFILE);
__END__

=head1 mnt.pl

Image device

=head1 SYNOPSIS

mnt.pl [options] [file ...]

Options:

--outdir     Where mmls output is (MANDATORY)

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

B<mnt.pl> will search for the windows directory on partitions on a drive
=cut
