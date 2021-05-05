#!/usr/bin/perl 

#===================================================================================
# Written by: Keven Murphy
#
# Used for mass triage of systems, the script will parse the WMI db and present
# the output in a CSV '|' delimited format. This allows for easy frequency analysis.
#
#
# Requirements:
# wmi_consumerbindings_csv_v0.2.py
#
# Author Notes:
# 1) See only the uniq lines: (head -n1 wmi.csv && tail -n +2 wmi.csv | sort -u) > {filename}
# 2) To see only the uniq lines without the source file path: (head -n1 wmi.csv && cut -d\| -f1-7 wmi.csv | sort -u) > {filename}
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
use File::Path;
use Encode;
use Pod::Usage;
use threads;
use threads::shared;
use Thread::Queue;
use Carp::Assert;
use IO::File 1.14;

$version = 0.2;
my $process_q = Thread::Queue -> new();
my $mftfnd,$logfilefnd,$jfnd = 0;


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

    my $cnt = 0;
    my $left = 0;
    my $pausecnt = 0;

    
    foreach $wmidir (@wmidirs) {
      $process_q->enqueue ( $wmidir );
    }
    $process_q->end();
    
    print "Processing queued files...\n";
    for (0..$maxthread) {
       threads -> create ( \&worker );
    }
    
    my @threadlist = threads->list(threads::running);
    my $num_threads = $#threadlist;
    print "Waiting for $num_threads threads to complete processing files...\n";
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
      print "Waiting for $num_threads threads to complete processing files...\n";
    }

}

sub worker {

  while ( my $wmidirworker = $process_q -> dequeue() )
  {
    chomp ( $wmidirworker );
    print "\tThread " .threads -> self() -> tid(). ": Reviewing $wmidirworker\n";
    
    eval {
       wmiparse($wmidirworker);
    };
    if ($process_q ->pending() ne "") {
        print "Number of files left to review: ".$process_q ->pending()."\n";
     } else {
    }
  }

}

sub wmiparse {
   my ($wmidir) = @_;
   my $wmicboptstmp = $wmicbopts;
   $wmicboptstmp =~ s/DIR/$wmidir/g;
   print "$wmicb  $wmicboptstmp\n";
   #chdir($tmpdir) or die "Process: Cannot change directory to $tmpdir -- Error: $!";
   print "\tWorking on: $wmidir\n";
   open DATA, "$wmicb  $wmicboptstmp |"   or die "Couldn't execute program: $!";
   while ( defined( my $line = <DATA> )  ) {
      chomp($line);
      print "$line\n";
   }
   close DATA;
        #print "$dircwd\n";
   chdir($dircwd) or die "Process: Cannot change directory to $dircwd  -- Error: $!";
}


#=============================================================================================
# file_process
#=============================================================================================
sub file_process {
    #my ($file) = @_;

    $options =~ s/OUTFILE/$savedir/g;
    print "\n\n$ntfslinkerbin  $options \n\n\n";

    open DATA, "$ntfslinkerbin  $options |"   or die "Couldn't execute program: $!";
    while ( defined( my $line = <DATA> )  ) {
      chomp($line);
      print "$line\n";
    }
    close DATA;

}
#=============================================================================================


#=============================================================================================
# Process
#=============================================================================================
sub process {

#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_


#Need to create links to the orginal files as the WMI tool has to have the original filenames in order to work.

    #Match on INDEX.BTR
    if ($_ =~ m/^INDEX.*\.BTR?/) {
       #my $newfile = addslash(getcwd)."INDEX.BTR";
       #my $error = symlink(addslash(getcwd).$_, $newfile);
       my $tmpdir = $dir."/".$File::Find::dir;
       push(@wmidirs, $tmpdir)
    }
    #if ($_ =~ m/MAPPING1.*\.MAP?/) {
       #my $newfile = addslash(getcwd)."MAPPING1.MAP";
       #my $error = symlink(addslash(getcwd).$_, $newfile);
    #}    
    #if ($_ =~ m/MAPPING2.*\.MAP?/) {
       #my $newfile = addslash(getcwd)."MAPPING2.MAP";
       #my $error = symlink(addslash(getcwd).$_, $newfile);
    #}    
    #if ($_ =~ m/MAPPING3.*\.MAP?/) {
       #my $newfile = addslash(getcwd)."MAPPING3.MAP";
       #my $error = symlink(addslash(getcwd).$_, $newfile);
    #}    
    #if ($_ =~ m/OBJECTS.*\.DATA?/) {
       #my $newfile = addslash(getcwd)."MAPPING3.MAP";
       #my $error = symlink(addslash(getcwd).$_, $newfile);
    #}     
    #if($_ eq "INDEX.*\.BTR_") {
    #  my $tmpdir = $dir."/".$File::Find::dir;
    #  push(@wmidirs, $tmpdir);
    #}

     
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

#[wmi]
#savedir=wmi
#consumerbindings=/appl2/wmi/wmi_consumerbindings_csv.py
#consumerbindings_opts=--path DIR --type win7 --out OUTFILE


my $Config = Config::Tiny->read( $config );
if (defined $config) {
    $savedirconfig=$Config->{wmi}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $wmicb=$Config->{wmi}->{consumerbindings};
    $wmicbopts=$Config->{wmi}->{consumerbindings_opts};
    $maxthread=$Config->{wmi}->{maxthread};
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================

#=============================================================================================
# Setup environment to begin work
#=============================================================================================
$dircwd = getcwd();
my $abs_path = abs_path();
chomp($dircwd);

my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
$year += 1900; 
my $savefileout = "wmi_cb_".$year."_".$mon."_".$mday.".csv";

$savedir = $dircwd . "/" . $savedirconfig;
#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create directory $savedir\n";
}

$savedir .= "/" . $savefileout;
$wmicbopts =~ s/OUTFILE/$savedir/g;

$dir = $dircwd;
#$mftfilename = $dir."/\$MFT";
#$md5logfilename =  $savedir . "/md5log";
print "Reviewing mount point for the wmi repo files: $mntdrive\n";
print "Saving wmi output file to: $savedir\n";
print "Config File Used: $config\n";
#chdir($dir) or die "Cannot change directory to $dir -- Error: $!";


#=============================================================================================

#=============================================================================================
# Start of plugin code
#=============================================================================================
@wmidirs;

#Find the MFT
find(\&process, $mntdrive);
threadprocess2;



__END__

=head1 wmi.pl

Image device

=head1 SYNOPSIS

wmi.pl [options] [file ...]

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

B<wmi.pl> will process the WMI databases in a mass triage capacity. WMI databases for each machine must be in separate directories.

Files Required:
OBJECTS.DATA
MAPPING1.MAP
MAPPING2.MAP
MAPPING3.MAP
INDEX.BTR

=cut
