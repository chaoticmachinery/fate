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
use Time::Local;
use DateTime;
use Image::ExifTool;

$version = 0.01;


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
# process
#=============================================================================================
sub process {
    #my ($) = @_;
    my @output = ();
#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_

    my $file_out = `file \"$_\"`;

    switch ($file_out) {
      case /executable/    {@output = `$yarabin $yarasig \"$_\"`;}
      case /Document/      {@output = `$yarabin $yarasig \"$_\"`;}
      
      else {}
    }
    chomp(@output);
    if (@output) {
      my $logline = "";
      foreach my $line (@output) {
	 $logline .= $line;
      }
      $logline =~ s/$_//g;
      my $pathlog = $File::Find::name;
      $pathlog =~ s/$dir//g;
      open (OUT2, ">> $outfile");
      print OUT2 "$pathlog: $logline\n";
      close(OUT2);
    }
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
    $savedirconfig=$Config->{getfiles}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $timezone=$Config->{default}->{timezone};
    #$yarabin=$Config->{yara}->{yarabin};
    #$yarasig=$Config->{yara}->{yarasig};   
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
my $taskdir = "";
my $activetimebias = 0;
my $fndactivetimebias = 0;

$savedir = $dircwd . "/" . $savedirconfig;
$dir = $dircwd;
$md5logfilename =  $savedir . "/md5log";
print "Searching $dir for Yara hits.\n";
print "Saving Yara hits files to: $savedir\n";
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

$savedir = addslash($savedir);
$outfile = $savedir . "yarascan.txt";
open (OUT, "> $outfile");
print OUT "Get Files\n\n";


chdir($savedir);
$result = `(cd ../drive/Windows/System32/; tar cf - winevt) | tar xvf -`;
	use File::Copy;
copy("../drive/\$MFT","MFT") or die "Copy failed: $!";
#$result = `cp  "../drive/$MFT" .`;
#/Windows/System32/winevt/


print "Done.\n";

close(OUT);



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
