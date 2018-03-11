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


$version = 0.01;
my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my @weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);
my $time = "";

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
# Get the start time
#=============================================================================================
$starttime=Benchmark->new;
#=============================================================================================

GetOptions ("mntdrive=s"   => \$mntdrive      # output directory
           ) ||  pod2usage(-verbose => 0);
		      
    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory arguement '--mntdrive' is missing}
		 -exitval => 1,
		 -verbose => 1 }
	) unless ($mntdrive);

my @plugins = (<$opt_p/*.pl>);
	
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
    $mntpath=$Config->{mntpath}->{mntpath};
    $pluginsdir=$Config->{process}->{plugindir};
    $pluginsdir=$directories.$pluginsdir;
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

my @plugins = (<$pluginsdir/*.pl>);


$mntdrive = addslash($mntdrive);
make_path("$mntdrive");
$mntpath = addslash($mntpath);
$drvmntpath = $mntdrive.$mntpath;

print "\n\nUsing config: $config\n";
print "Using plugins in: $pluginsdir\n";
print @plugins."\n";
print "Reviewing partition at: $drvmntpath\n";

foreach $plugin (@plugins) {
  print "\n\nRunning plugin: $plugin\n";
  print "$plugin --mntdrive $mntdrive\n";
  $pluginruntext = "$plugin --mntdrive $mntdrive";
  print "PLUGIN: $pluginruntext\n";
  #$plugintext = `$plugin --mntdrive $mntdrive`;
  open(PLUGINRUN, "$pluginruntext |") || die "Failed: $!\n";
  while (<PLUGINRUN>) {
      print "\t$_";
  }
  close(PLUGINRUN);
  $time = currenttime();
  sendemail("$plugin complete","$plugin has completed running at $time.\n");
}
$time = currenttime();
#=============================================================================================
# Get the start time
#=============================================================================================
$endtime=Benchmark->new;
#=============================================================================================
$maintime =  timestr(timediff($endtime, $starttime), 'all');
sendemail("Imaging and Plugins has completed.",
          "Imaging and Plugins has completed running at $time.\nTotal Run Time: $maintime\n");

__END__

=head1 mnt.pl

Image device

=head1 SYNOPSIS

mnt.pl [options] [file ...]

Options:

--mntdrive     Where mmls output is (MANDATORY)

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
