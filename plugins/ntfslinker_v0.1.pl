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

$version = 0.1;

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

     my $orglog = "";


     my($type) = "";
     open(FILE, $_) or die("Error reading file, stopped");
     read(FILE, $type, 5);
     if ($type eq "FILE0") {
        my $newfilename = addslash($savedir) . $_;
        #my $orgfile = $_;
        #$newfilename =~ s/\$/\\\$/g;
        $newfilename =~ s/\ /\\\ /g;
        #$orgfile =~ s/\$/\\\$/g;
        #$orgfile =~ s/\ /\\\ /g;
   

        if ($links > 0) {
            print "\tSymlink $orgfile to\n\t\t$newfilename\n";
            my $symlinkerror = symlink($orgfile,$newfilename);
            print "$symlinkerror \n";
          } else {
            print getcwd."\n";
            print "copy  $_    $newfilename\n";
            copy("$_", "$newfilename") or die "File cannot be copied: $! \"$_\" to \"$newfilename\"";        
        }
        $mftfnd = 1;
     }
     if ($type =~ m/^RSTR/) {
        my $newfilename = addslash($savedir) . $_;
        if ($links > 0) {
            print "\tSymlink $_ to\n\t\t$newfilename\n";
            my $symlinkerror = symlink($orgfile,$newfilename);
          } else {
            print "copy  $_    $newfilename\n";
            copy("$_", "$newfilename") or die "File cannot be copied: $! \"$_\" to \"$newfilename\"";
        }
        $logfilefnd = 1;
     }
     close(FILE);
     if ($_ =~ m/\$J/) {
        my $newfilename = addslash($savedir) . $_;
        if ($links > 0) {
            print "\tSymlink $_ to\n\t\t$newfilename\n";
            my $symlinkerror = symlink($orgfile,$newfilename);
          } else {
            print "copy  $_    $newfilename\n";
            copy("$_", "$newfilename") or die "File cannot be copied: $! \"$_\" to \"$newfilename\"";
        }
        $jfnd = 1;
     }
     
     if ($mftfnd > 0) {
       if ($logfilefnd > 0) {
         if ($jfnd > 0) {
           file_process();
         }
       }
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
    $savedirconfig=$Config->{ntfslinker}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $ntfslinkerbin=$Config->{ntfslinker}->{ntfslinkerbin};
    $options=$Config->{ntfslinker}->{options};
    $links=$Config->{ntfslinker}->{links};
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
#$analyzemftopts =~ s/SAVEDIR/$savedir/g;

$dir = $dircwd;
#$mftfilename = $dir."/\$MFT";
#$md5logfilename =  $savedir . "/md5log";
print "Reviewing mount point for MFT,LogFile, and UsrJrnl:J files: $mntdrive\n";
print "Saving NTFS_Linker output file to: $savedir\n";
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
find(\&process, $mntdrive);



__END__

=head1 ntfslinker.pl

Image device

=head1 SYNOPSIS

ntfslinker.pl [options] [file ...]

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

B<ntfslinker.pl> requires the following files: MFT,LogFile, and UsrJrnl:J (ADS)

Simply put it creates a history of the file system activity on NTFS volume. 

See https://strozfriedberg.github.io/ntfs-linker/ for more information and the tool must be installed.
=cut
