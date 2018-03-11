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

sub sendemail_working {
    my ($subject,$message) = @_;

my $mail = new Mail::SendEasy(
  smtp => $smtpsrv
  ) ;

    my $status = $mail->send(
    from    => $emailfrom ,
    reply   => $emailfrom ,
    to      => $emailto ,
    subject => $subject ,
    msg     => $message ,
    );# or die "Can't open the message: $mail->error\n";
  if (!$status) { print $mail->error ;die;}
}




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
# Split Files
#=============================================================================================
sub split_files {
   print "Splitting file up into 2200 meg files ...\n";
   $splitfilename = $archivefile . "_";
   @splitoutput = `split --verbose -b $splitsize $archivefile $splitfilename | cut -f3 -d" "`;
   chomp(@splitoutput);
   @splitoutput = map { $_ =~ s/\`//g; $_ } @splitoutput;
   @splitoutput = map { $_ =~ s/\'//g; $_ } @splitoutput;
   print "\tListing of split files:\n";
   foreach $output (@splitoutput) {
	   print "\t$output\n";
   }
}
#=============================================================================================

#=============================================================================================
# Md5 split files
#=============================================================================================
sub md5_split_files {
   print "\nCreating MD5 hashes for split files and saving output as $archivefile.md5 ...\n";
   my $md5deepfiles = $splitfilename."*";
   $archivefilemd5 = $archivefile.".md5";
   @md5deepoutput = `md5deep -e -l -j 4 @splitoutput | tee $archivefilemd5`;
   chomp(@md5deepoutput);
   print "\tHashes saved to $archivefile.md5\n";
   print "\tList of md5 hashes for split files\n";
   foreach $output (@md5deepoutput) {
	   print "\t$output\n";
   }
}
#=============================================================================================

#=============================================================================================

GetOptions ("file=s"   => \$archivefile      # output directory
           ) ||  pod2usage(-verbose => 0);
		      
    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory arguement '--file' is missing}
		 -exitval => 1,
		 -verbose => 1 }
	) unless ($archivefile);

	
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
    $md5deep=$Config->{dvdimage}->{md5deep};
    $md5deepthreads=$Config->{dvdimage}->{md5deep};
    $workdir=$Config->{dvdimage}->{workdir};   
    $splitsize=$Config->{dvdimage}->{splitsize};       
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================


#=============================================================================================
# Burn DVD
#=============================================================================================
sub burn_dvd {

  my ($drv, $archivefilemd5, $file0, $file1) = @_;
  
  #$output = `growisofs -dvd-compat -speed=16 -R -J -pad -Z /dev/$drv $archivefilemd5 $file0 $file1`
  print "growisofs -dvd-compat -speed=16 -R -J -pad -Z /dev/$drv $archivefilemd5 $file0 $file1\n";
  threads->exit();
}
#=============================================================================================



print "\n\nUsing config: $config\n";

if ($workdir eq "") {
   $workdir = getcwd;
}
print "Using work directory: $workdir\n";

print "\nDetermining DVD writers....\n";

@dvdwriters = `dmesg | egrep -i writer | cut -f2 -d] | cut -f1 -d:|cut -f2 -d' '`;
chomp(@dvdwriters);

foreach $drv (@dvdwriters) {
	print "\t$drv\t";
	my $drvdir = "/mnt/".$drv;
	print "Creating dvd mount directory: $drvdir\n";
	mkdir $drvdir;
}	
print "\n";

#Max # of threads due to drives
$maxthreads = $#dvdwriters;


split_files();
md5_split_files();

#$archivefilemd5="glasglow2.tar.gz.md5";
$drv="sr0";

while(1) {

   my $burnfilecount = $#splitoutput;
   for ($cnt = 0; $cnt >= $burnfilecount; $cnt++) {
      my $file0 = $splitoutput[$cnt];
      my $file1 = "";
      $cnt++;
      if ($cnt <= $burnfilecount) {
      	 $file1 = $splitoutput[$cnt];
      }
      @threadlist = threads->list;
      $num_threads = $#threadlist; 
      if ($num_threads < $maxthreads) {
      	$thread = threads->create( \&burn_dvd, $drv, $archivefilemd5, $file0, $file1);
      }
   }
}

print "Waiting for DVDs to finish...\n";
do {
@threadlist = threads->list();
$num_threads = threads->list();
print "\tWaiting for $num_threads to finish burning.\n";
sleep(5);
} until ($num_threads <= 0);






#growisofs -dvd-compat -speed=16 -R -J -pad -Z /dev/$@ && \
#sleep 20 && \
#mount /dev/$1 /mnt/$1 && \
#cd /mnt/$1 && \
#md5deep -e -X ./$2 * 
#cd $CURRENTDIR
#umount /dev/$1
