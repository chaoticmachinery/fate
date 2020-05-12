#!/usr/bin/perl 

#use warnings;
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


my $version = 0.1;
my $OS = "winxp";
my $regkey = "ProductName";

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
# Determine the OS type for Windows
#=============================================================================================
sub determineos {
    #my ($getpartionstart) = @_;

   my $value = "";
   my $ProductName = "";
   my $srchfilename = lc($_);
   if ($srchfilename =~ /software$/) {
      my $fileout = `file \"$File::Find::name\"`;
      chomp($fileout);
      my $reglog = "";
      my $hash = "";
      if ($fileout =~ /\bregistry\b/i) {
	  print "\tSearching $File::Find::name\n"  if $verbose;

	  my $line = 0;
	  open(REGSRCH, "$regfind  \"$File::Find::name\" $regkey -v |") || die "Failed: $!\n";
	  while (<REGSRCH>) {
	      if ($_ =~ /\\Microsoft\\Windows NT\\CurrentVersion/) {
		$line++;
              }
	      if ($line > 0) {
		  ($ProductName, $value) = split(/=/,$_);
		  last;
	      }
	  }
	  close(REGSRCH);

      }
   }

   lc($value);
   #print "VALUE: $value\n";
   switch ($value) {
       case /xp/ 	{ $OS = "winxp"; }
       case /7/ 	{ $OS = "win7"; }
       case /vista/ 	{ $OS = "win7"; }
       case /server/     { $OS = "winsrv"; }
       else		{ $OS = "linux"; }
   }
   #print "VALUE: $OS\n";

}
#=============================================================================================

#=============================================================================================
# Start of MAIN
#=============================================================================================
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
    $savedirconfig=$Config->{log2timeline}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $timescannerbin=$Config->{log2timeline}->{timescanner};
    $flsbin=$Config->{default}->{fls};    
    $timezone=$Config->{default}->{timezone};
    $mactime=$Config->{default}->{mactime};
    $fastprocess=$Config->{log2timeline}->{fastprocess};
    $regfind=$Config->{log2timeline}->{regfind};
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

$savedir = $dircwd . "/" . $savedirconfig;
$savedir = addslash($savedir);
$dir = addslash(abs_path($mntdrive));
$md5logfilename =  $savedir . "/md5log";

print "Gathering data from $dir.\n";
print "Saving log2timeline files to: $savedir\n";
print "Config File Used: $config\n";
chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create $savedir\n";
}
#=============================================================================================



#=============================================================================================
# Start of plugin code
#=============================================================================================

#Need to determine what version of OS the image is
print "Determining OS version...";
find(\&determineos, $dir);
print "  Done.\n";
print "Running Log2TimeLine $OS modules on image.\n";

print "Running Log2TimeLine timescanner....\n";
#my $timescannertext = $timescannerbin . " -zone " . $timezone;
#$timescannertext .= " -format ".$OS." "; #Format of the image
#$timescannertext .= " -preprocess "; #Preprocess
#$timescannertext .= " -recursive "; #recursive
#$timescannertext .= " -write ".$savedir."timescanned.bodyfile";
#$timescannertext .= " -log " .$savedir."timescanned.bodyfile.log";
#$timescannertext .= " -detail ".$dir;

#timescanner  -zone UTC -format win7  -write /log2timeline/timescanned.bodyfile -log /log2timeline/timescanned.bodyfile.log -d ./drive
my $timescannertext = $timescannerbin . " -zone " . $timezone;
$timescannertext .= " -format ".$OS." "; #Format of the image
$timescannertext .= " -write ".$savedir."timescanned.bodyfile";
$timescannertext .= " -log " .$savedir."timescanned.bodyfile.log";
$timescannertext .= " -d ".$dir;

$timescannertext = $timescannerbin . " -zone UTC -format ".$OS."  -write ".$savedir."timescanned.bodyfile -log " .$savedir."timescanned.bodyfile.log -d ".$dir;

print "CMD: $timescannertext\n";
open(TIMESCANNER, "$timescannertext |") || die "Failed: $!\n";
while (<TIMESCANNER>) {
    print "\t$_";
}
close(TIMESCANNER);

print "Completed command.\n"





__END__

=head1 sample.pl

Image device

=head1 SYNOPSIS

sample.pl [options] [file ...]

Options:

--mntdrive     Where output date should go and where image is mounted (MANDATORY)

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

B<sample.pl> will 
=cut
