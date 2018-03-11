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
use Encode;
use Pod::Usage;

$version = 0.01;

#=============================================================================================
# mft_process
#=============================================================================================
sub mft_process{
    my ($file) = @_;
    $cleanfile = $file;
 
    my $dircwd = getcwd();
    chomp($dircwd);
    $file =~ s/\$/\\\$/g;
    $mftfile = $dircwd . "/";
    $mftfile .= $file;
    
    
    my $options = $analyzemftopts;
    $cleanfile =~ s/\$//g;
    
    $cleanfile_OUTFILE = $cleanfile."_OUTFILE";
    $cleanfile_BODYFILE= $cleanfile."_BODYFILE";
    $cleanfile_CSVFILE = $cleanfile."_CSVFILE.csv";
    
    $options =~ s/OUTFILE/$cleanfile_OUTFILE/g;
    $options =~ s/BODYFILE/$cleanfile_BODYFILE/g;
    $options =~ s/CSVFILE/$cleanfile_CSVFILE/g;
    
    #print "$analyzemft -f $mftfile $options \n";
    open DATA, "$analyzemft -f $mftfile $options |"   or die "Couldn't execute program: $!";
    while ( defined( my $line = <DATA> )  ) {
      chomp($line);
      print "$line\n";
    }
    close DATA;

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
# Process
#=============================================================================================
sub process {

#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_

     my $orglog = "";

     my($type) = "";
     open(FILE, $_) or die("Error reading file, stopped");
     read(FILE, $type, 5);
     if ($type eq "FILE0") {
        mft_process($_);
     }
     close(FILE);
     
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
    $savedirconfig=$Config->{analyzemft}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $analyzemft=$Config->{analyzemft}->{analyzemft};
    $analyzemftopts=$Config->{analyzemft}->{options};
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================

#=============================================================================================
# Setup environment to begin work
#=============================================================================================
my $dircwd = getcwd();
my $abs_path = abs_path();
chomp($dircwd);

$savedir = $dircwd . "/" . $savedirconfig;
$analyzemftopts =~ s/SAVEDIR/$savedir/g;

$dir = $dircwd;
$mftfilename = $dir."/\$MFT";
$md5logfilename =  $savedir . "/md5log";
print "Reviewing mount point for MFT files: $mntdrive\n";
print "Saving analyzeMFT output file to: $savedir\n";
print "Config File Used: $config\n";
#chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create $savedir\n";
}
#=============================================================================================

#=============================================================================================
# Start of plugin code
#=============================================================================================


#Find the MFT
find(\&process, $mntdrive);



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
