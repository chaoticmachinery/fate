#!/usr/bin/perl 
#===================================================================================
# Written by: Keven Murphy
#
# Used for mass triage of systems, the script will parse the bitsadmin dat files and present
# the output in a csv format. This allows for easy frequency analysis.
#
#
# Requirements:
# https://github.com/ANSSI-FR/bits_parser
#
# Author Notes:
# 1)  cut -f13 -d, *.csv | sort | uniq -c | sort -rn

#
# Mod Log:
#===================================================================================
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
use File::Path qw(make_path);
use threads;
use threads::shared;
use Thread::Queue;
use Encode;
use Pod::Usage;

$version = "0.1";
my @fileslistkeys;
my %filelisthash;
my $flcnt = 0;
my $process_q = Thread::Queue -> new();
my $verbose = 0;


#=============================================================================================
# mft_process
#=============================================================================================
sub bits_process{
    my ($bitsfiletmp) = @_;
    $cleanfile = $bitsfiletmp->{file};

    #print "$bitsfiles[0]->{filename}\n";
    #print "$bitsfiles[0]->{file}\n";
    #print "$bitsfiles[0]->{dir}\n";

    
    my $mntfile = "\"".addslash($filelisthash{$file}).$file."\"";
    $mntfile =~ s/\$/\\\$/g;

    #Create the output directory
    $tmpcreatedir = addslash($bitsfiletmp->{dir});
    #$tmpcreatedir =~ s/^..//;   #Strip off the 1st 2 characters i.e. "./"
    $createdir = addslash($savedir).$tmpcreatedir;
    make_path($createdir, {verbose => 1});
    $createdir = addslash($createdir).$bitsfiletmp->{filename};
    
    my $tmpanalyzemftopts = $bitsparseropts;
    $tmpanalyzemftopts =~ s/OUTPUT/\"$createdir.csv\"/g;
    $tmpanalyzemftopts =~ s/INPUT/\"$bitsfiletmp->{file}\"/g;   
    my $options = $tmpanalyzemftopts;
    $cleanfile =~ s/\$//g;
    #print "CF: $cleanfile\n";
    #print "AS: ".addslash($File::Find::dir)."\n";
    #print "OPTIONS: $options\n";
    #print "SD: $savedir\n";
    
    print "CMD: $bitsparser $options \n" if $verbose;

    print "\n\n";
    
    open DATA, "$bitsparser $options |"   or die "Couldn't execute program: $!";
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
# Process the files
#=============================================================================================
sub threadprocess2 {

    #my ($fn) = @_;
    #print "$bitsfiles[0]->{dir}\n";
    
    my $cnt = 0;
    my $left = 0;
    my $pausecnt = 0;
    
    foreach my $bitfiletmp (@bitsfiles) {    
      $process_q -> enqueue ( $bitfiletmp );
    }
    $process_q -> end();
    
    
    
    for (0..$maxthread) {
       threads -> create ( \&worker );
    }
    
    #Wait for threads to all finish processing.
    #foreach my $thr ( threads -> list() ) {
    #   $thr -> join();
    #}
    my @threadlist = threads->list(threads::running);
    my $num_threads = $#threadlist;
    print "Waiting for $num_threads to complete...\n";
    while($num_threads != -1) {
      sleep(1);
      foreach $thr (threads->list) {
        @threadlist = ();
        # Don't join the main thread or ourselves
        if ($thr->tid && !threads::equal($thr, threads->self)) {
            $thr->join;
        }
      }
      @threadlist = threads->list;
      $num_threads = $#threadlist;
      print "Waiting for $num_threads to complete...\n";
    }

}

sub worker {
  while ( my $bitsfiletmp = $process_q -> dequeue() )
  {
    chomp ( $bitsfiletmp->{file} );
    
    print "\tThread " .threads -> self() -> tid(). ": Reviewing $bitsfiletmp->{file}\n";
    
    eval {
       bits_process($bitsfiletmp);
    };
    if ($process_q ->pending() ne "") {
        print "Number of files left to review: ".$process_q ->pending()."\n";
     } else {
    }
  }

}

#=============================================================================================
# Process
#=============================================================================================
sub process {

#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_

     my $orglog = "";
   
     my($tmptype) = "";
     open(FILE, $_) or die("Error reading file, stopped");
     read(FILE, $tmptype, 8);
     my ($type) = unpack 'H*', $tmptype;

     #Check the file sig to see if it matches.
     if ($type eq "2832ed09a6c7e945") {
       push(@bitsfiles, { filename=>$_, file=>$File::Find::name ,dir=>$File::Find::dir });
       push(@bitsdir, $File::Find::dir);
     }
     
     close(FILE);
     
}
#=============================================================================================


#=============================================================================================

GetOptions ("mntdrive=s"   => \$mntdrive,      # output directory
            "help|?" => \$opt_help,
            "man" => \$opt_man
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
    $savedirconfig=$Config->{bitsadmin_oldos}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $bitsparser=$Config->{bitsadmin_oldos}->{bitsparser};
    $bitsparseropts=$Config->{bitsadmin_oldos}->{options};
    $threadapp=$Config->{bitsadmin_oldos}->{thread};
    $maxthread=$Config->{bitsadmin_oldos}->{maxthread};
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
#$analyzemftopts =~ s/SAVEDIR/\"$savedir/g;

$dir = $dircwd;
$mftfilename = $dir."/\$MFT";
$md5logfilename =  $savedir . "/md5log";
print "Reviewing mount point for qmgr.db files: $mntdrive\n";
print "Saving bitsadmin output file to: $savedir\n";
print "Config File Used: $config\n";
print "Note: This plugin will recreate the directory structure in the save directory for any processed file.\n";
#chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create $savedir\n";
}
#=============================================================================================

#=============================================================================================
# Start of plugin code
#=============================================================================================
@bitsfiles;
@bitsdir;

print "Searchng for qmgr0.dat and qmgr1.dat files.\n";
find({ wanted => \&process, follow => 1}, $mntdrive);
$bitsfilesnum = $#bitsfiles+1;
print "\tNumber of qmgr0.dat and qmgr1.dat files found: $bitsfilesnum\n";
print "Processing Files....\n";

threadprocess2;

__END__

=head1 bitsadmin_oldos.pl

Image device

=head1 SYNOPSIS

bitsadmin_oldos.pl [options] [file ...]

Options:

--mntdrive   Data to be processed (MANDATORY)

--help       Brief help message

--man        Full documentation

=head1 OPTIONS

=over 8

=item B<--mntdrive>

Where the image is mounted that needs to be processed (MANDATORY).
-OR- 
The directory with the data that needs to be processed (MANDATORY).

=item B<--help>

Print a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<bitsadmin_oldos.pl> will look for the qmgr0.dat and qmgr1.dat files. Once found the files will be passed to the bits parser.
=cut
