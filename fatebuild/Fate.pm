package Fate;

require Exporter;
@ISA = (Exporter);

use File::Find;
use File::Copy;
use File::Basename;
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

$VERSION = 0.01;


=head1 NAME

Fate common subroutines

=head1 SYNOPSIS

   use Fate;


=head1 DESCRIPTION

This module provides 
=cut

@EXPORT = qw( addslash,
	      workdir;
            );

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

#=========================================================================
# Setup directory to search
#=========================================================================
sub workdir {

    my ($mntdrive) = @_;

    $dir = addslash($mntdrive);
    #Need to convert relative paths to absolute
    $dir = File::Spec->rel2abs( $dir ) ;
    if (-d $dir) {
      } else {
	print "$dir DOES NOT exist!\n\n";
	exit;
    }
    return($dir);
}
#=========================================================================

#=========================================================================
# Setup directory to search
# copyfile($File::Find::dir,$File::Find::name,$_,1);
#=========================================================================
sub drvpath {

    my ($fnddir,$searchdrive)=@_;

    my $searchdrivelen = length($searchdrive);
    my $newpath = substr($fnddir,$searchdrivelen+1);

    return($newpath);

}
#=========================================================================


1;
