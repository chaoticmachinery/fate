#!/usr/bin/perl

use Config::Tiny;
use Getopt::Long;
use Pod::Usage; 
use File::Basename;
use Cwd 'abs_path';
use Cwd;
use Switch;
use File::Find;
use File::Path qw(make_path);
use Net::SMTP::TLS;
use Net::SMTP;
use Benchmark;
use threads;
use threads::shared;

$version = 0.01;
my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my @weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);
my $time = "";
my $num_threads = 0;
my $emailbody = "";

#=============================================================================================
# currenttime
#=============================================================================================
sub currenttime {
    #my ($path) = @_;

    my ($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek,$dayOfYear, $daylightSavings) = localtime();
    my $year = 1900 + $yearOffset;
    my $currenttime = "$hour:$minute:$second, $weekDays[$dayOfWeek] $months[$month] $dayOfMonth, $year";
    return($currenttime);
}
#=============================================================================================

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
# Send Email Notification
#=============================================================================================
sub sendemail {

    my ($subject,$message) = @_;

    my $mailer;

    if ($tls eq "n") {
	$mailer = Net::SMTP->new($smtpsrv);
      } else {
	#GMAIL code
	$mailer = new Net::SMTP::TLS(
	    $smtpsrv,
	    Hello   =>      $smtpsrv,
	    Port    =>      $smtpport,
	    User    =>      $smtpuser,
	    Password=>      $smtppassword);
    }

    $mailer->mail($emailfrom);
    $mailer->to($emailto);
    $mailer->data();
    $mailer->datasend("From: " . $emailfrom . "\n");
    $mailer->datasend("To: " . $emailto . "\n");
    $mailer->datasend("Subject: " . $subject ."\n");
    $mailer->datasend("\n");
    $mailer->datasend($message."\n");
    $mailer->dataend;
    $mailer->quit;
}


#=============================================================================================

#=============================================================================================
# Get device info
#=============================================================================================
sub get_drive_info {
   my ($device,$filename,$sleuthkitdir,$savedir) = @_;
   
   $device = "/dev/".$device;
   $savedir = addslash($savedir);
   
   print "Getting hard drive information...\n";
   system ("$sleuthkitdir/mmls -B $device > $savedir$filename.mmls 2>&1");
   print "\tmmls\n";
   system ("fdisk -lu $device > $savedir$filename.fdisk 2>&1");
   print "\tfdisk\n";
   system ("sfdisk -luS $device > $savedir$filename.sfdisk 2>&1");
   print "\tsfdisk\n";	
   system ("hdparm -giI $device > $savedir$filename.hdparm 2>&1");
   print "\thdparm\n";

   if ($device_name_short =~ /^sd/) {
	   system ("sg_inq -d  $device > $savedir$filename.sginq_d 2>&1");
           print "\tsg_inq -d\n";
	   system ("sg_inq -E  $device > $savedir$filename.sginq_E 2>&1");
           print "\tsg_inq -E\n";
	   system ("sginfo -d $device > $savedir$filename.sginfo_d 2>&1");
	   print "\tsginfo -d\n";
	   system ("sginfo -A $device > $savedir$filename.sginfo_A 2>&1");
	   print "\tsginfo -A\n";
	   system ("sg_readcap $device > $savedir$filename.sgreadcap 2>&1");
	   print "\tsg_readcap\n";
   }
   print "Done with device information gathering.\n\n";
}
#=============================================================================================

#=============================================================================================
# Image Device
#=============================================================================================
sub image_device {
    my ($device,$filename) = @_;
    
    my $ddoptions = $dc3ddopt;
    $ddoptions =~ s/DRIVE/\/dev\/$device/;
    $ddoptions =~ s/FILENAME/$imagename/g;
    #print "\n$dc3dd $ddoptions \n";
    open(IMAGE, "$dc3dd $ddoptions 2>&1 |");
    while ($line = <IMAGE>) {
    
    	if ($line =~ "copied") {
	   } else { 
    	     $status .= $line;
	}
    }
    close(IMAGE);
    return($status);
}
#=============================================================================================

#*********************************************************************************************
# MAIN  **************************************************************************************
#*********************************************************************************************

#=============================================================================================
# Get the start time
#=============================================================================================
$starttime=Benchmark->new;
#=============================================================================================

#=============================================================================================

GetOptions ("device=s"		=> \$device,    # Drive to image
	    "imagename=s"	=> \$imagename, # Filename for the image
	    "process"		=> \$process	# Process image
           ) ||  pod2usage(-verbose => 0);
		      
    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory arguement '--imagedrive' is missing}
		 -exitval => 1,
		 -verbose => 1 }
	) unless ($device && $imagename);


	
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
    $sleuthkitdir=$Config->{sleuthkit}->{sleuthkitdir};
    $dc3dd=$Config->{image2}->{dc3dd};
    $dc3ddopt=$Config->{image2}->{dc3ddopt};
    $emailto=$Config->{emailnotificition}->{to};
    $emailfrom=$Config->{emailnotificition}->{from};
    $smtpsrv=$Config->{emailnotificition}->{smtp};
    $tls=$Config->{emailnotificition}->{tls};
    $smtpport=$Config->{emailnotificition}->{port};
    $smtpuser=$Config->{emailnotificition}->{userid};
    $smtppassword=$Config->{emailnotificition}->{password};    
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================

#=============================================================================================
# Setup environment to begin work
#=============================================================================================
my $dircwd = getcwd();
chomp($dircwd);
my $savedir = $dircwd;

print "\n\nUsing config: $config\n";
$device_name_short=$device;
$device_name_short=~ s/\/dev\///g;
print "Imaging Device: $device_name_short\n"; 
print "Saving image and output files to: $savedir\n";
print "\tAll saved related to imaging will start with: $imagename\n";

print "Gathering device information...\n";
my $status = get_drive_info($device_name_short,$imagename,$sleuthkitdir,$savedir);

print "Starting imaging...";
#$status = image_device($device_name_short,$imagename);
print " done.\n";

print "Output from imaging:\n$status\n";

$time = currenttime();
#=============================================================================================
# Get the end time
#=============================================================================================
$endtime=Benchmark->new;
#=============================================================================================
$maintime =  timestr(timediff($endtime, $starttime), 'all');
my $inmin = (timestr(timediff($endtime, $starttime)))/ 60;

$status = "Imaging has completed running at $time.\nTotal Run Time: $maintime or $inmin minutes\n".$status;
sendemail("Imaging completed.",$status);

if ($process) {

  #MNT image
  my $cmdoptions = ""; # None needed for mnt.pl
  my $cmd = "\"".$directories."mnt.pl\" |";
  open(MNT, $cmd) || die "Cannot execute $cmd (mnt.pl): $!\n";
  my $fnd = 0;
  while (my $line = <MNT>) {
    if ($line =~ /Mounted at:/) {
	print "LINE: $line\n";
	$fnd++;
    }
    if ($fnd > 0) {
	($tmp, $mnt) = split(/:/, $line);
	chomp($mnt);
	$mnt =~ s/^\s+//;
	my $outputdir = $mnt."_out";
	mkdir($outputdir);
	chdir($outputdir);
	
	print "Processing the partition.\n";
	print "Saving output to: $outputdir\n";
	my $cmdoptions = "--mntdrive ".$mnt; # None needed for process_thread.pl
	my $cmd = "\"".$directories."process_thread.pl\" ".$cmdoptions." |";
	open(PROCESSTHREAD, $cmd) || die "Cannot execute $cmd (process_thread.pl): $!\n";
	while (my $line = <PROCESSTHREAD>) {
	    print $line;
	}
	close(PROCESSTHREAD);
	print "Done with processing partition.\n";
	chdir($savedir);
    }
  }
  close(MNT);


}


__END__

=head1 image.pl

Image device

=head1 SYNOPSIS

image2.pl [options] 

Options:

--device        The device to image (MANDATORY)

--imagename     The name of the image file (MANDATORY)

--process	After making the image, process it for evidence

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
