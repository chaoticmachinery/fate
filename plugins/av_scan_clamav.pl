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
use Fate;

$VERSION = 0.01;


#=====================================================================================================================
# Start of MAIN
#=====================================================================================================================

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
    $savedirconfig=$Config->{clamav}->{savedir};
    $clamscanopts=$Config->{clamav}->{clamscanoptions};   
    $driveconfig=$Config->{default}->{drive};
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


#=========================================================================
# Setup directory to search and save directory
#=========================================================================
$savedir = $dircwd . "/" . $savedirconfig;
$dir = Fate::workdir($mntdrive);
#=========================================================================

$md5logfilename =  $savedir . "/md5log";
$clamlogfilename =  $savedir . "/clamscan.log";
$infectedfiles = $savedir . "/infected";

print "Saving sample files to: $savedir\n";
print "Config File Used: $config\n";
print "Saving Clamscan log to: $clamlogfilename\n";
print "Saving a copy of malicious files to: $infectedfiles\n";
chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create $savedir\n";
}
#Creating the infectedfiles directory
unless(-e $infectedfiles or mkdir $infectedfiles) {
	die "Unable to create $infectedfiles\n";
}
#=============================================================================================


#=============================================================================================
# Start of plugin code
#=============================================================================================
print "Updating Clam database\n";
$error = `freshclam`;
print "Starting Scan\n";
$error = `clamscan $clamscanopts --log=$clamlogfilename --copy=$infectedfiles`;


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
