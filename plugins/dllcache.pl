#!/usr/bin/perl 

#use warnings;
use File::Find;
#use File::Find::Rule;
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

my $VERSION = 0.01;
my $dllcachefiles = ();
my $system32dir = "";

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
# Do a md5 on the file
#=============================================================================================
sub md5file {
    my ($filename) = @_;
    
    
    if (-e $filename) {
	  open (FILE, "< $filename");
	  binmode FILE;
	  
	  $md5 = Digest::MD5->new;
	  while (<FILE>) {
	      $md5->add($_);
	  }
	  close(FILE);
	  $hash = $md5->hexdigest;
      } else {
	$hash = "FILE DOES NOT EXIST";
    }
    
    return $hash;
}
#=============================================================================================

#=============================================================================================
# Write MD5 to file
#=============================================================================================
sub md5log {
    my ($newfilename2,$sNewString, $hash) = @_;

    my $md5filename = $savedir.$newfilename2 . ".md5";
    open (MD5Log, ">> $md5filename");
    print MD5Log "$hash  $sNewString\n";
    close MD5log;

    return;
}
#=============================================================================================

#=============================================================================================
# Copy Reg file to our Save directory
#=============================================================================================
sub copyfile {
  my ($newfilenametmp,$cpfile,$filename) = @_;
  
  $newfilename = $savedir.$newfilenametmp;
  copy($cpfile, $newfilename) or die "File cannot be copied: $!\nOLD: $cpfile\nNEW: $newfilename\n";
  my $md5 = md5file($newfilename);
  md5log($filename, $newfilename, $md5);

  return;
}

#=============================================================================================


#=============================================================================================
# Process
#=============================================================================================
sub process {
    my ($getpartionstart) = @_;

    #my $found = 0;

    $srchfilename = lc($_);
    my $dir = lc($File::Find::dir);
    if ($dir =~ /system32\/dllcache/) {
        $system32dir = $File::Find::dir;

	#my ($filename, $directories, $suffix) = fileparse($File::Find::name);
	#$dllcachefiles{$filename} = md5file($File::Find::name);
	
	return();
    }
    
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
    $savedirconfig=$Config->{dllcache}->{savedir};
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

$savedir = $dircwd . "/" . $savedirconfig;
$savedir = addslash($savedir);
$dir = $dircwd;
$md5logfilename =  $savedir . "/md5log";
print "Gathering data from $dir.\n";
print "Saving log files to: $savedir\n";
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
print "Searching for dllcache....\n";
$dllcachepath = find(\&process, $dir);
print "Found dllcache at: $system32dir\n";
$dllcachepath = $system32dir;

print "Generating md5 hashes of dllcache...\n";
$system32dir =~ s/dllcache//;

chdir($dllcachepath);
my @dllcachefilesnames = <*>;

foreach $file (@dllcachefilesnames) {
	my $newfilename = lc($file);
	$dllcachefiles{$newfilename} = md5file($file);
	#print "$file = $dllcachefiles{$file}\n";
}
#print "$dllcachepath\n";



$outfile = $savedir . "dllcache.txt";
open (OUT, "> $outfile");
print OUT "DLL Cache Hash Comparison\n\n";

print "Generating md5 hashes of system32...\n";
chdir($system32dir);
my @contents_system32 = <*>;

my %system32files = ();
foreach $file (@contents_system32) {
	my $newfilename = lc($file);
	$system32files{$newfilename} = md5file($file);
}	
	
print "Searching system32 for malware...\n";	
while ( my ($key, $value) = each(%dllcachefiles) ) { 	
	if ($value ne $system32files{$key}) {
	     if ($system32files{$key} eq "") {
		  #print "\tFile not found in system32: $key: $value\n";
		  print OUT "\tFile not found in system32: $key: $value\n";
		} else {
		  print "\tWARNING - Doesn't match $key: $value != $system32files{$key}\n";
		  print OUT "\tWARNING - Doesn't match $key: $value != $system32files{$key}\n";
		  my $system32file = addslash($system32dir) . $key;
		  if (-e $system32file) {
		     } else {
		       $system32file = addslash($system32dir) . uc($key);
		  }
		  my $system32file_new = $key . "_system32";
		  my $dllcachefile = addslash($dllcachepath) . $key;
		  if (-e $dllcachefile) {
		     } else {
		       $dllcachefile = addslash($dllcachefile) . uc($key);
		  }  
		  my $dllcachefile_new = $key . "_dllcache";
		  copyfile($system32file_new,$system32file,$key); 
		  copyfile($dllcachefile_new,$dllcachefile,$key);
	     }
	   } else {
	     print OUT "\tMatches: $key: $value = $system32files{$key}\n";
	}
}
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
