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
    open FILE, "$filename";
    binmode FILE;
    my $data = <FILE>;
    close FILE;
    $hash = md5_hex($data);
    return $hash;
}
#=============================================================================================

#=============================================================================================
# Write MD5 to file
#=============================================================================================
sub md5log {
    my ($newfilename2,$sNewString, $hash) = @_;

    my $md5filename = $newfilename2 . ".md5";
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
        my ($newfilename,$cpfile,$nameoffile,$doit) = @_;

        my $arrynum = 0;

        #$newfilename = $File::Find::dir;
        #print "DIR: $newfilename\n";

        #Subtract the $dir path from the found path
        my $iIndex = length ($dir);
        my $sNewString = substr($newfilename, $iIndex + 1);

        #Creating the save directory
        my $RegDirSave = $savedir . $sNewString;
        print "\tCreating directory: $RegDirSave\n" if $verbose;
        unless(-e $RegDirSave or &File::Path::mkpath($RegDirSave)) {
                die "Unable to create $RegDirSave directory to backup files\n$!\n";
        }

        my $cpfile = $File::Find::name;
        my $newfilename2 = $RegDirSave . "/" . $nameoffile;

        if ($doit == 1) {
                print "\tCopying $cpfile to\n\t\t$newfilename2\n";
                copy($cpfile, $newfilename2) or die "File cannot be copied: $!";

                print "\tCalculating MD5 for $cpfile and\n\t\t$newfilename2\n" if $verbose;
                my $md5 = md5file($cpfile);
                my $md52 = md5file($newfilename2);
                if ($md52 ne $md5) {
                    die "Error: MD5 hashes for $cpfile and $newfilename2 do not match\n";
                }

                my $pathfilename = $sNewString . "/" . $nameoffile;
                md5log($newfilename2,$pathfilename, $hash);
                md5log($md5logfilename,$pathfilename, $hash);


                #Need to alter our file and pathname to create a symbolic link.
                #remove our found directory path from filename
                $newfilename =~ s/$dir//g;
                #remove periods
                $newfilename =~ s/.//;
                #remove spaces in filename
                $newfilename =~ s/\s+/_/g;
                #Using = to replace / (or directory indicators)
                $newfilename =~ s/\//=/g;
                #remove any dashes
                $newfilename =~ s/-//;
                $newfilename = $newfilename . "=" .$_;
                $newfilename = $savedir . $newfilename;
                $cpfile = $File::Find::name;

                print "\tSymlink $cpfile to\n\t\t$newfilename\n" if $verbose;
                my $symlinkerror = symlink($newfilename2, $newfilename);
                if ($symlinkerror != 1) {
                    if ($! =~ /File exists/) {
                      } else {
                        die "$symlinkerror -- Cannot create symbolic links: $!";
                    }
                }
        }

        return $newfilename;
}
#=============================================================================================


#=============================================================================================
# findsystem32
#=============================================================================================
sub process {
    my ($getpartionstart) = @_;

    #my $found = 0;
    
    $srchfilename = lc($_);


    #Contains information about device changes, driver changes, and major system changes, such as service pack 
    #installations and hotfix installations. Per http://support.microsoft.com/kb/927521 
    if ($srchfilename =~ /setupapi\.log/) {
        $reglog = copyfile($File::Find::dir,$File::Find::name,$_,1);
    }

    #Contains information about application installation. Per http://support.microsoft.com/kb/927521
    if ($srchfilename =~ /setupapi\.app\.log/) {
        $reglog = copyfile($File::Find::dir,$File::Find::name,$_,1);
    }

    #Contains information about Plug and Play devices and driver installation. 
    #Per http://support.microsoft.com/kb/927521
    if ($srchfilename =~ /setupapi\.dev\.log/) {
        $reglog = copyfile($File::Find::dir,$File::Find::name,$_,1);
    } 

    #Driver failures during the Component Specialization sub-phase of the Setup specialize phase. 
    #Per http://technet.microsoft.com/en-us/library/ee851579%28v=ws.10%29.aspx
    if ($srchfilename =~ /setupapi\.offline\.log/) {
        $reglog = copyfile($File::Find::dir,$File::Find::name,$_,1);
    }  

    #Primary log file for most errors that occur during the Windows installation process.
    #Per http://technet.microsoft.com/en-us/library/ee851579%28v=ws.10%29.aspx
    if ($srchfilename =~ /setupact\.log/) {
        $reglog = copyfile($File::Find::dir,$File::Find::name,$_,1);
    }  

    #High-level list of errors that occurred during the specialize phase of Setup.
    #Per http://technet.microsoft.com/en-us/library/ee851579%28v=ws.10%29.aspx
    if ($srchfilename =~ /setuperr\.log/) {
        $reglog = copyfile($File::Find::dir,$File::Find::name,$_,1);
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
    $savedirconfig=$Config->{setup_api_log}->{savedir};
    $driveconfig=$Config->{default}->{drive}; 
    $timezone=$Config->{default}->{timezone};
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
print "Searching....\n";
find(\&process, $dir);
print "Done.\n"







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
