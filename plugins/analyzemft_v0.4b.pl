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
use File::Path qw(make_path);;
use threads;
use threads::shared;
use Thread::Queue;
use Encode;
use Pod::Usage;

$version = "0.4";
my @fileslistkeys;
my %filelisthash;
my $flcnt = 0;
my $process_q = Thread::Queue -> new();


#=============================================================================================
# mft_process
#=============================================================================================
sub mft_process{
    my ($file) = @_;
    $cleanfile = $file;
 
 
#    my @filelistkeys = keys %filelisthash;
#    for my $fl (@filelistkey) {
#       print "FL: $fl  Dir: $filelisthash{$fl}\n";
#    }

    
    my $mntfile = "\"".addslash($filelisthash{$file}).$file."\"";
    $mntfile =~ s/\$/\\\$/g;
    #print "mntfile: $mntfile\n";

    #Create the output directory
    #$createdir = "\"".addslash($filelisthash{$file})."\"";
    #print "AA: $createdir\n";
    #eval { make_path($createdir) };
      
    my $options = $analyzemftopts;
    $cleanfile =~ s/\$//g;
    #print "CF: $cleanfile\n";
    #print "AS: ".addslash($File::Find::dir)."\n";
    #print "OPT: $options\n";
    #print "SD: $File::Find::dir\n";

    # Remove ./ from the path
    #my $firstchars = substr($cleanfile,0,2);
    #print "1:$firstchars\n";
    #if ($firstchars eq "./") {
    #   $cleanfile = substr($cleanfile,2);
    #}    
    
    #$cleanfile_OUTFILE =  addslash($File::Find::dir).$cleanfile."_OUTFILE\"";
    $cleanfile_OUTFILE =  $cleanfile."_OUTFILE\"";
    #print "A:".$cleanfile_OUTFILE."\n"."A:".$cleanfile."_OUTFILE"."\n";
    $cleanfile_BODYFILE=  $cleanfile."_BODYFILE\"";
    $cleanfile_CSVFILE =  $cleanfile."_CSVFILE.csv\"";
    
    $options =~ s/OUTFILE/$cleanfile_OUTFILE/g;
    $options =~ s/BODYFILE/$cleanfile_BODYFILE/g;
    $options =~ s/CSVFILE/$cleanfile_CSVFILE/g;
    
    print "CMD: $analyzemft -f $mntfile $options \n";

    print "\n\n";
    #exit(0);
    
    open DATA, "$analyzemft -f $mntfile $options |"   or die "Couldn't execute program: $!";
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
     open(FILE, $_) or die("Error reading file, stopped");
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
    $threadapp=$Config->{analyzemft}->{thread};
    $maxthread=$Config->{analyzemft}->{maxthread};
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
$analyzemftopts =~ s/SAVEDIR/\"$savedir/g;

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
find({ wanted => \&process, follow => 1}, $mntdrive);
print "\tFound: $flcnt\n";
print "Processing Files....\n";
threadprocess2;

__END__

=head1 analyzemft.pl

Image device

=head1 SYNOPSIS

analyzemft.pl [options] [file ...]

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

B<analyzemft.pl> will parse all of the MFT files it finds in a given directory path.
=cut
