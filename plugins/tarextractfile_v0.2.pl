#!/usr/bin/perl
# Written by: Keven Murphy
# Description: Will extract a single file from the tar file.
#
# Version: 0.2
#
# Example: find ./systems -name "etc.tar.gz" -exec ./tarextractfile.pl --tarfile {} --xfile "etc/file" \;;  find . -name "file" -exec md5sum {} \; | sort
#

use Archive::Tar;
use File::Basename;
use Getopt::Long;
use Cwd qw(cwd);
use Data::Dumper;


my $currentdir = cwd;


$result = GetOptions ("xfile=s"   => \$xfile,      # File to extract
                    "tarfile=s"   => \$tarfile,    # tar file
					"find"		=> \$srch,         # Find file regardless of path
                    "verbose"  => \$verbose);      # verbose

my $tar = Archive::Tar->new;
$tar->read($tarfile);

print "Working on: $tarfile\n";
print "Searching for: $xfile\n";
$ndir = $tarfile;
$ndir =~ s/\.\.//g;
$ndir =~ s/\//=/g;


if ($tar->contains_file( $xfile ) )   {
   unless(-e $ndir or mkdir $ndir) {
       die "Unable to create $ndir\n";
   }
   chdir($ndir);
   if ($tar->extract($xfile)) {
       print "\tWritten file to: $ndir\n";
     } else {
       print "\t Error: Could not extract file.\n";
   } 
   chdir($currentdir);
}

if (defined $srch) {
	my @listfiles = $tar->list_files();
	print Dumper(@listfiles);
	my @matches = grep /$xfile/i, @listfiles;
	print @matches;

    unless(-e $ndir or mkdir $ndir) {
       die "Unable to create $ndir\n";
    }
    chdir($ndir);
	foreach $line (@matches) {	   
        if ($tar->extract($line)) {
            print "\tWritten file to: $ndir\n";
          } else {
            print "\t Error: Could not extract file.\n";
        } 
       chdir($currentdir);	
	}
}
