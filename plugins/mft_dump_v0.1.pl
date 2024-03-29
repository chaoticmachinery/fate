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

$version = "0.1";
my @fileslistkeys;
my %filelisthash;
my $flcnt = 0;
my $process_q = Thread::Queue -> new();
my $verbose = 1;


#=============================================================================================
# mft_process
#=============================================================================================
sub mft_process{
    my ($file) = @_;
    $cleanfile = $file;
 
    
    my $mntfile = "\"".addslash($filelisthash{$file}).$file."\"";
    $mntfile =~ s/\$/\\\$/g;
    #print "mntfile: $mntfile\n";

    #Create the output directory
    $tmpcreatedir = addslash($filelisthash{$file});
    #if ($tmpcreatedir =~ "./") {
    #   $tmpcreatedir =~ s/^.//;   #Strip off the 1st 2 characters i.e. "./"
    #}
    $createdir = addslash($savedir).$tmpcreatedir;
    #print "CD1:==$createdir==\n";
    #eval { make_path($createdir) };
    make_path($createdir, {verbose => 1});
    
    my $tmpmftdumpopts = $mftdumpopts;
    $tmpmftdumpopts =~ s/SAVEDIR/\"$createdir/g;
    my $options = $tmpmftdumpopts;
    $cleanfile =~ s/\$//g;
    #print "CF: $cleanfile\n";
    #print "AS: ".addslash($File::Find::dir)."\n";
    #print "OPTIONS: $options\n";
    #print "SD: $savedir\n";

    $cleanfile_OUTFILE =  $cleanfile."_OUTFILE.csv\"";
    
    $options =~ s/OUTFILE/$cleanfile_OUTFILE/g;
    
    print "CMD: $mftdump $options $mntfile \n" if $verbose;

    print "\n\n";
    #exit(0);
    
    open DATA, "$mftdump $options $mntfile |"   or die "Couldn't execute program: $!";
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

    my $cnt = 0;
    my $left = 0;
    my $pausecnt = 0;
    
#    foreach my $mftfiletmp (@filelist) {
    foreach my $mftfiletmp (@filelistkeys) {    
      $process_q -> enqueue ( $mftfiletmp );
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
       mft_process($mftfiletmp);
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
     open(FILE, $_) or warn("Error reading file: $_ - $!");
     read(FILE, $type, 5);
     if ($type eq "FILE0") {
        #$filelist[$flcnt] = $File::Find::name;
        #$filelist[$flcnt] = "\"".$File::Find::fullname."\"";
	    $flcnt++;
        #mft_process($_);
        $filelisthash{$_} = $File::Find::dir;
     }
     close(FILE);
     @filelistkeys = keys %filelisthash;
     
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
    $savedirconfig=$Config->{mftdump}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $mftdump=$Config->{mftdump}->{mftdump};
    $mftdumpopts=$Config->{mftdump}->{options};
    $threadapp=$Config->{mftdump}->{thread};
    $maxthread=$Config->{mftdump}->{maxthread};
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
print "Reviewing mount point for MFT files: $mntdrive\n";
print "Saving analyzeMFT output file to: $savedir\n";
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


#Find the MFT
#find(\&process, $mntdrive);
print "Searchng for MFT files.\n";
#find(\&process, $mntdrive);	
find({ wanted => \&process, follow => 1, follow_skip => 2}, $mntdrive);
print "\tNumber of MFT files found: $flcnt\n";
print "Processing Files....\n";
threadprocess2;

__END__

=head1 mft_dump.pl

Image device

=head1 SYNOPSIS

mft_dump.pl [options] [file ...]

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

B<mft_dump.pl> will parse all of the MFT files it finds in a given directory path. Ideally set the number of threads to 60 to 70% of the total number of cores that are available in the plugins.ini file. 
=cut
