#!/usr/bin/perl 

#use warnings;
use File::Find;
use File::Copy;
use File::Basename;
use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(sha1_hex);
use Cwd 'abs_path';
use Cwd;
use Switch;
use Getopt::Long;
use Config::Tiny;
use File::Path;
use Pod::Usage;
use Time::Local;
use DateTime;
use File::stat;
use File::Spec;
use Fate;

my $VERSION = 0.01;


#=============================================================================================
# process
#=============================================================================================
sub process {
    #my ($) = @_;
    my @output = ();
    my $md5digest = "";
#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_

    #my $filesize = stat(\"$_\")->size;
    my $filesize = -s $File::Find::name;
    #print "Mx: $maxfilesize - Size: $filesize - $File::Find::name\n";
    if ($maxfilesize >= $filesize) {
      #my $md5 = file_md5_hex( "\"$_\"" );
      if (-f $File::Find::name) {
	  if (open(FILE, $File::Find::name)) {  # or die "Can't find file \"$File::Find::name\"\n";
	      #open(FILE, $File::Find::name) or die "Can't open '$filename': $!";
	      binmode(FILE);
	      $md5digest = Digest::MD5->new->addfile(*FILE)->hexdigest();
	      $sha1digest = Digest::SHA->new->addfile(*FILE)->hexdigest();
	      close(FILE);
	      chomp($md5digest);
	      $md5digest = uc($md5digest);
	      
	      open(FILE, $File::Find::name);
	      binmode(FILE);
	      $sha1digest = Digest::SHA->new->addfile(*FILE)->hexdigest();
	      close(FILE);
	      chomp($sha1digest);
	      $sha1digest = uc($sha1digest);
	  }

	  my $filename_path = $File::Find::name;
	  $filename_path =~ s/$dir//;
	  
	  if (exists $hashes{$md5digest}) {
	      open (OUT2, ">> $outfile");
	      print OUT2 "\"$md5digest\";\"$filename_path\"\n";
	      close(OUT2);
	  }
	  
	  if (exists $hashes{$sha1digest}) {
	      open (OUT2, ">> $outfile");
	      print OUT2 "\"$sha1digest\";\"$filename_path\"\n";
	      close(OUT2);
	  }
	  
	  if ($hashsavefile ne "") {
	      open (OUT2, ">> $hashoutfile");
	      print OUT2 "\"$md5digest\";\"$sha1digest\";$filesize;\"$filename_path\"\n";
	      close(OUT2);
	      
	      #MD5,SHA1,filesize,filename
	  }	  
      } 
    }
    
    
}
#=============================================================================================

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
    $savedirconfig=$Config->{hashsearch}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $timezone=$Config->{default}->{timezone};
    $hashlistfile=$Config->{hashsearch}->{hashlist};
    $maxfilesize=$Config->{hashsearch}->{maxfilesize};
    $patternsplit=$Config->{hashsearch}->{patternsplit};
    $hashsavefile=$Config->{hashsearch}->{hashsavefile};
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

my $taskdir = "";
my $activetimebias = 0;
my $fndactivetimebias = 0;



#=========================================================================
# Setup directory to search and save directory
#=========================================================================
$savedir = $dircwd . "/" . $savedirconfig;
$dir = Fate::workdir($mntdrive);
#=========================================================================

$md5logfilename =  $savedir . "/md5log";

print "Searching $dir for hash hits.\n";
print "Saving hash hits files to: $savedir\n";
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

$savedir = Fate::addslash($savedir);
$outfile = $savedir . "hashhits.txt";
if ($hashsavefile ne "") {
    $hashoutfile = $savedir . $hashsavefile;
}

#==========================================================
# Read in hashlist
#==========================================================
print "Max file size to be hashed: $maxfilesize\n";
print "Using hashlist located at: $hashlistfile\n";
print "Using $patternsplit to split fields in hash list file.\n";
open FILE, "$hashlistfile" or die $!;
my $key = "";
%hashes = ();
while ($line=<FILE>){
 chomp($line);
 my $firstchar = substr $line, 0, 1;
 if ($firstchar ne "#") {
    $line = uc($line);
    my (@parts) = split($patternsplit, $line);
    if ($parts[0] ne "") {
	$hashes{$parts[0]} = $parts[0];
    }
 }
}
close(FILE);
#==========================================================

open (OUT, "> $outfile");
print OUT "Hash Scan\n\n";
print OUT "Max file size to search is: $maxfilesize\n";
close(OUT);

open (OUT, "> $hashoutfile");
print OUT "Hash Save CSV File\n\n";
print OUT "MD5,SHA1,filesize,filename\n";
close(OUT);


#find({ wanted => \&process, follow => 1,follow_skip==2}, $dir);


find(\&process, $dir);
print "Done.\n";




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
