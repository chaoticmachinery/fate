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
#use strict;
use warnings;

my $version = 0.1;

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
    $savedirconfig=$Config->{plaso_log2timeline}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $log2timelinebin=$Config->{plaso_log2timeline}->{log2timeline};
    $log2timelineopts=$Config->{plaso_log2timeline}->{plaso_opts};
    $plaso_savefile=$Config->{plaso_log2timeline}->{plaso_savefile};
    $workercnt=$Config->{plaso_log2timeline}->{workercnt};
    $psortcmd=$Config->{plaso_log2timeline}->{psortcmd};
    $psort_opts=$Config->{plaso_log2timeline}->{psort_opts};
    $psort_log=$Config->{plaso_log2timeline}->{psort_log};
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
print "Saving Plaso Log2timeline files to: $savedir\n";
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

print "Running Plaso Log2TimeLine timescanner....\n";

# log2timeline.py --preprocess --partition all --zone UTC   --disable_zerom -al
# --logfile {logfile} --status_view linear
# --workers {define core -2}  {plaso} {image or directory}


$worker = $workercnt;
#if ($workercnt < 1) {
#    $cores = `nproc`;
#    chomp($cores);
#    print "Number of cores detected: $cores\n";
#    print "Number of workers per config: $workercnt\n"; 
#    #Turn out negative to a positive. :)
#    $workercnt = $workercnt * -1;
#    $worker = $cores - $workercnt;
#    print "Number of workers used: $worker\n";
#}

#my $l2tltext = $log2timelinebin ." ". $log2timelineopts . " --workers " . $worker ." ";
my $l2tltext = $log2timelinebin ." ". $log2timelineopts . " ";
$l2tltext .= $savedir.$plaso_savefile." ";
$l2tltext .= $dir;

print "CMD: $l2tltext\n";
#open(TIMESCANNER, "$l2tltext |") || die "Failed: $!\n";
#while (<TIMESCANNER>) {
#    print "\t$_";
#}
#close(TIMESCANNER);

print "Running psort...\n";
chdir($savedir);
my $psortcmd = $psortcmd." ".$psort_opts." --write ".$savedir."/l2tl_bodyfile.csv ".$savedir."l2tl_bodyfile.plaso";
print "psortcmd: $psortcmd\n";
open(TIMESCANNER, "$psortcmd |") || die "Failed: $!\n";
while (<TIMESCANNER>) {
    print "\t$_";
}
close(TIMESCANNER);
chdir($dircwd);

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
