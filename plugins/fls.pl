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
print "FLS Plugin Version: $version\n\n";

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
# Addslash
#=============================================================================================
sub checkmntdrive {
    my ($mntdrive) = @_;

    my $lastchar =  substr($mntdrive,length($mntdrive)-1,1);
    if ($lastchar eq "/") {
	chop($mntdrive);
    }
    return($mntdrive);
}
#=============================================================================================


#=============================================================================================
# getpartition
#=============================================================================================
sub getpartition {
    my ($mntdrive) = @_;

    my $text = "";

    #Need to determin OS
    my $OS = `uname -s`;

    if ($OS =~ /Linux/) {
        #The lines below are Linux centric.

        #Determine where the image file is mounted
        #Need to use the -w with grep so that matches return exactly as required
        chdir($mntdrive) || die "$mntdrive does not exist.";
        my $abspath = getcwd();
        $text = `df -h | grep -w $abspath`;
        $text =~ s/\h+/ /g;
        print "CMD: $mntdrive -- $text\n";
        @fields = split(/\h/, $text);
        switch ($fields[0]) {
          case /loop/ {
            #Take the output of losetup to determine the file used for mounting and offset for parition
            $looptext = `losetup -a | grep $fields[0]`;
            @loopfields = split(/\h/, $looptext);
	    chomp(@loopfields);
            $loopfields[2] =~ s/\(//;
            $loopfields[2] =~ s/\)//;
            $loopfields[2] =~ s/,//;
            $mntfile = $loopfields[2];
            #Determine the offset by dividing by 512
            $offset = $loopfields[4]/512;
          }
          case /sd/ {
            $mntfile = $fields[0];
            $offset = 0;
          }
          else {
          }
       }
       return($mntfile,$offset);
      } else {

        #The lines below are OSX centric.

        #Determine where the image file is mounted
        #Need to use the -w with grep so that matches return exactly as required
        $text = `df | grep ewfmount`;
        $text =~ s/\h+/ /g;
        @fields = split(/\h/, $text);
        chomp $fields[5];
        my $hdiutil = `hdiutil info  | grep \"$fields[5]\" | grep path`;
        $hdiutil  =~ s/\h+/ /g;
        my ($ewfmnt, $colon, $ewfpath) =  split(/\h/, $hdiutil);      
        chomp $ewfpath;
 
        #This section is used to determine offset.
        $text = `df | grep \"$dir\"`;
        $text =~ s/\h+/ /g;
        @fields = split(/\h/, $text);
        print "FIELD: $fields[0]\n";

        #Need to determine the disk that is mounted and chop off the parition
        my $disk = $fields[0];
        $disk  =~ s/s\d+\b//;

        #Need to determine the partition
        my @partitionfields = split(/\//, $fields[0]);
        my $partition = $partitionfields[2];
        $partition =~ s/disk\d+s//;

        my $linecnt = 1;
        @partitionfields = [];
        open(FLS, "fdisk -d $disk |") || die "Failed: $!\n";
        while (<FLS>) {
            if ($linecnt == $partition) {
               my @partitionfields = split(/,/, $_);
               $offset = $partitionfields[0];   #*512;                
               last;
            }
            print "$_";
            $linecnt++;
        }
        close(FLS);
        
        return($ewfpath,$offset);
    }

}
#=============================================================================================

#=============================================================================================

GetOptions ("mntdrive=s"   => \$mntdrive,      # output directory
            "verbose" => \$verbose
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
    $savedirconfig=$Config->{fls}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $flsbin=$Config->{default}->{fls};    
    $timezone=$Config->{default}->{timezone};
    $mactime=$Config->{default}->{mactime};
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
$currDir = `pwd`; chomp $currDir;print "CURRENTDIR: $currDir\n";
$savedir = $dircwd . "/" . $savedirconfig;
$savedir = addslash($savedir);
#$dir = $dircwd . "/" . $driveconfig;
$dir = $dircwd;
$md5logfilename =  $savedir . "/md5log";
print "Gathering data from $dir.\n";
print "Saving fls files to: $savedir\n";
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

$mntdrive = checkmntdrive($mntdrive);
print "Running fls....\n";
my ($mntfile,$offset) = getpartition($mntdrive);
chdir($mntdrive);
if ($mntfile eq "") {
   die "FLS PLUGIN ERROR: Could not determine where image is mounted to.\n";
}

my $flstext = $flsbin . " -m C: -r -z ".$timezone." -o $offset $mntfile";
#my $flstext = $flsbin . " -m C: -r  $mntfile";
$flstext .= " > ".$savedir."fls.mactime";
print "\tRunning the following cmd: $flstext\n" if $verbose;
open(FLS, "$flstext |") || die "Failed: $!\n";
while (<FLS>) {
    print "\t$_";
}
close(FLS);
my $mactimelog = " > ".$savedir."fls.bodyfile";
$flstext = $mactime . " -d -h -z ".$timezone." -b ".$savedir."fls.mactime ";
$flstext .= $mactimelog;
print "Converting fls mactime file to bodyfile...\n";
print "Converting fls mactime file to bodyfile using cmd: $flstext\n" if $verbose;
$error = `$flstext`;
print "fls gathering complete.\n";

print "Creating human readable fls output\n";
my $flstext = $flsbin . "  -l -p  -r -z ".$timezone." -o $offset $mntfile";
$flstext .= " > ".$savedir."fls.human";
print "\tRunning the following cmd: $flstext\n" if $verbose;
open(FLS, "$flstext |") || die "Failed: $!\n";
while (<FLS>) {
    print "\t$_";
}
close(FLS);
print "Completed fls output\n";

#open(FLS, "$flstext |") || die "Failed: $!\n";
#while (<FLS>) {
#    print "\t$_";
#}
#close(FLS);
#fls -m -C: -r -o $PART $DDFILE > ./timeline/$DDFILE




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
