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
    $savedirconfig=$Config->{strings_pagefile}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $strings=$Config->{strings_pagefile}->{strings};
    $ascii_options=$Config->{strings_pagefile}->{ascii_options};
    $unicode_options=$Config->{strings_pagefile}->{unicode_options};    
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
$dir = $dircwd;
$md5logfilename =  $savedir . "/md5log";
print "Searching $dir for sample files.\n";
print "Saving sample files to: $savedir\n";
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
$pagefile = "pagefile.sys";
print "Running strings on: $pagefile\n";
$ascii_out = addslash($savedir)."strings_pagefile_ascii.txt";
$unicode_out = addslash($savedir)."strings_pagefile_unicode.txt";
print "Saving ASCII output to: $ascii_out\n";
print "Saving UNICODE output to: $unicode_out\n";
print "Pulling ASCII out of the $pagefile...";
$error = `$strings $ascii_options $pagefile > $ascii_out 2>&1`;
print "Done.\n";
print "Pulling UNICODE out of the $pagefile...";
$error = `$strings $unicode_options $pagefile > $unicode_out 2>&1`;
print "Done.\n";






__END__

=head1 strings_pagefile.pl

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

B<strings_pagefile.pl> will 
=cut
