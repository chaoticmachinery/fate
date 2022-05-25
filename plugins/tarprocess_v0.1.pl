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
use File::Path qw(make_path);
use threads;
use threads::shared;
use Thread::Queue;
use Encode;
use Pod::Usage;
use File::Spec;

$version = "0.1";
my @fileslistkeys;
my %filelisthash;
my $flcnt = 0;
my $process_q = Thread::Queue -> new();
my $verbose = 1;


#=============================================================================================
# tar_process
#=============================================================================================
sub tar_process{
    my ($file) = @_;
    $cleanfile = $file;
  
    print "CMD: $tardetails -i $file $tardetailsopts \n" if $verbose;

    print "\n\n";
    #exit(0);
    
    open DATA, "$tardetails -i $file $tardetailsopts |"   or die "Couldn't execute program: $!";
    while ( defined( my $line = <DATA> )  ) {
      chomp($line);
      #print "$line\n";
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

    my $cnt = 0;
    my $left = 0;
    my $pausecnt = 0;
    
    #print "@filelistkeys\n";
    foreach my $mftfiletmp (@filelistkeys) {    
      $process_q -> enqueue ( $mftfiletmp );
      #print "TP: $mftfiletmp \n";
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

  while ( my $mftfiletmp = $process_q -> dequeue() )
  {
    chomp ( $mftfiletmp );
    print "\tThread " .threads -> self() -> tid(). ": Reviewing $mftfiletmp\n";
    
    eval {
       tar_process($mftfiletmp);
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

     my($type) = "";

     if ($_ eq $processfile) {
        $filelistkeys[$flcnt] = $File::Find::name;
        $flcnt++;
     }  
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
    $savedirconfig=$Config->{tardetails}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $tardetails=$Config->{tardetails}->{tardetails};
    $tardetailsopts=$Config->{tardetails}->{options};
    $processfile=$Config->{tardetails}->{processfile};
    $threadapp=$Config->{tardetails}->{thread};
    $maxthread=$Config->{tardetails}->{maxthread};
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

$dir = $dircwd;
print "Reviewing mount point for tar files: $mntdrive\n";
print "Saving tardetails output file to: $savedir\n";
print "Config File Used: $config\n";

#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create $savedir\n";
}
#=============================================================================================

#=============================================================================================
# Start of plugin code
#=============================================================================================


#Find the tar files
print "Searchng for "+$processfile+" tar files.\n";
my $ap = abs_path($mntdrive);
#find({ wanted => \&process, follow => 1}, $mntdrive);
find({ wanted => \&process, follow => 1}, $ap);
print "\tNumber of "+$processfile+" files found: $flcnt\n";
print "Processing Files....\n";
chdir($savedir);
threadprocess2;
chdir($abs_path);

__END__

=head1 tarprocess.pl

Image device

=head1 SYNOPSIS

tarprocess.pl [options] [file ...]

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

B<tarprocess.pl> will extract the contents of tar files. Normally used with linux triage.
=cut
