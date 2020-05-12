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
use DateTime;
use File::Path::Tiny;

$version = 0.1;

#Get the date
my $dt = DateTime->now;
my $ymd = $dt->ymd;


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
# checksqlite
#=============================================================================================
sub chkdbsql {
    my ($database) = @_;
    my $dberror = 0;
    
    #die "Database file does not exist" unless -f "as2con.db";
    my $driver   = "SQLite"; 
    my $dsn = "DBI:$driver:dbname=$database";
    my $userid = "";
    my $password = "";
    #print "$dsn\n";
    #my $dbase = DBI->connect($dsn, "", "", {RaiseError => 1}) or die $DBI::errstr;
    my $dbh = DBI->connect($dsn, $userid, $password, { PrintError => 0, RaiseError => 0 });
    my $stmt = qq(SELECT * from review;);
    my $sth = $dbh->prepare( $stmt );
    #my $rv = $sth->execute(); # or die $DBI::errstr;
    if ($DBI::errstr) {
       print "DB: Error\n";
       $dberror = 0;
      } else {
       print "DB: Good\n";
       $dberror++;
    }
    $dbh->disconnect;
    return $dberror; 
}
#=============================================================================================

#=============================================================================================
# getreviewdb
#=============================================================================================
sub getreviewdb {
     #my () = @_;
     
     #Now run freq analysis through os_distill filecheck
     #print "$ir_file_distil -i $outfilesha -o $outfiledistilnsrl $ir_file_distil_opt $ir_file_distil_filecheck $ir_file_distil_reviewlist\n";
     print "Gathering reviewlist databases (Looking for .db)...\n";
     opendir(DIR, ".");
     my @reviewlistfiles = grep(/\.db$/,readdir(DIR));
     closedir(DIR);
     foreach $rlf (@reviewlistfiles) {
        print "\t$rlf\n";
     }
     
     my $rvlistopt = "";
     if (($#reviewlistfiles+1) <= 0) {
         print "\tNone found.\n";
       } else {
         print "Checking reviewlist sqlite databases...\n";
         my $dircwd = getcwd();
         
         foreach $rlf (@reviewlistfiles) {
            my $dberror = chkdbsql(addslash($dircwd). $rlf);
            if ($dberror >= 1) {
               $rblistopt .= " " . $ir_file_distil_reviewlist . " " .addslash($dircwd). $rlf;
               print "$rblistopt\n";
            }
         }
     }
     print "\n";
     return($rblistopt);
}
#=============================================================================================

#=============================================================================================
# Process
#=============================================================================================
sub process {

#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_

     my $step = 0;
     my ($mntdrive,$outfile) = @_;
     my $outfilereg = $outfile . ".txt";

     my $outfilensrl = $outfile . ".nsrl_nomatch";
     my $outfilefreq = $outfile . ".freq";
     my $outfiledistil = $outfile . ".distil";
     
     
     my $rblistopt = getreviewdb();
     
     
     #print "find $mntdrive -print -exec $regrip  -r {}  -p $regrip_amcache_plugin \\; > amcache_$ymd.txt \n";
     open(FNDOUT, '>', $outfilereg) or die "Could not open file '$outfilereg' $!";
     open(FND, "find $mntdrive -print -exec $regrip  -r {}  -p $regrip_shimcache_plugin \\\; |");
     #open(FND, "find $mntdrive -print -exec $wbamcache {} \\\; |");
     while ( defined( my $line = <FND> )  ) {
         chomp($line);
         print "$line\n" if $opt_v;
         print FNDOUT "$line\n";
     }
     close(FND);
     close(FNDOUT);
     print "\n\nCompleted with RegRipper.\n";


     #Step 1
     $step++; 
     my $nomatchlines = $outfile."_Step_".$step.".txt";     
     my $nsrlapptypecmd = "grep -a AppCompatCache ".$outfilereg." | grep -v Hive: | cut -f7 -d\\| | sort | uniq -c | sed -e 's/^[ \t]*//' | sort -t' ' -k2 ";
     open(freqanalysisout, '>', $nomatchlines) or die "Could not open file '$nomatchlines' $!";
     open(NSRLAppType, "$nsrlapptypecmd |");
     while ( defined( my $line = <NSRLAppType> )  ) {
         chomp($line);
         print "$line\n" if $opt_v;
         print freqanalysisout "$line\n";
     }
     close(NSRLAppType);    
     close(freqanalysisout);    
     print "\nExtracted fullpath and filenames from step 1. Created frequncy analysis file called: ".$nomatchlines."\n";
     
     #Step 2
     $step++;   
     my $outfiledistilfilecheck = $outfile ."_Step_".$step. ".filecheck_distil";     
     #Now run freq analysis through os_distill filecheck
     #print "$ir_file_distil -i $outfilesha -o $outfiledistilnsrl $ir_file_distil_opt $ir_file_distil_filecheck $ir_file_distil_reviewlist\n";
     print "$ir_file_distil --infile $nomatchlines --out $outfiledistilfilecheck $ir_file_distil_opt $ir_file_distil_filecheck $ir_file_distil_reviewlist $rblistopt\n";
     open(DISTIL, "$ir_file_distil --infile $nomatchlines --out $outfiledistilfilecheck $ir_file_distil_opt $ir_file_distil_filecheck $ir_file_distil_reviewlist  $rblistopt |");
     while ( defined( my $line = <DISTIL> )  ) {
         chomp($line);
         print "$line\n" if $opt_v;
         #print FNDOUT "$line\n";
     }
     close(DISTIL);    
     print "Review ".$outfiledistilfilecheck.".nomatch.txt as the final product.\n";
          
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
    $savedirconfig=$Config->{MassTriage}->{savedir};
    $nsrl=$Config->{MassTriage}->{nsrl};
    $nsrlopts=$Config->{MassTriage}->{nsrlopts};
    $nsrldb=$Config->{MassTriage}->{nsrldb};
    $ir_file_distil=$Config->{MassTriage}->{ir_file_distil};
    $ir_file_distil_filecheck=$Config->{MassTriage}->{ir_file_distil_filecheck}; 
    $ir_file_distil_nsrl=$Config->{MassTriage}->{ir_file_distil_nsrl}; 
    $ir_file_distil_reviewlist=$Config->{MassTriage}->{ir_file_distil_reviewlist};
    $ir_file_distil_opt=$Config->{MassTriage}->{ir_file_distil_opt};
    $regrip=$Config->{MassTriage}->{regrip};
    $regrip_shimcache_plugin=$Config->{MassTriage}->{regrip_shimcache_plugin};
    $wbamcache=$Config->{MassTriage}->{wbamcache};
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



$savedir = $dircwd . "/" . $savedirconfig. "/shimcache";
my $outfile = $savedir."/"."shimcache_".$ymd;

$dir = $dircwd;
print "Processing Shimcache files: $mntdrive\n";
print "Saving output to: $savedir\n";
print "Shimcache processing files start with: $outfile\n";
print "Config File Used: $config\n";
print "Note: This plugin will recreate the directory structure in the save directory for any processed file.\n";
#chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

#Creating the save directory
unless(-e $savedir or File::Path::Tiny::mk($savedir)) {
        die "Unable to create $savedir\n";
}
#=============================================================================================

#=============================================================================================
# Start of plugin code
#=============================================================================================


#Find the shimcache files
process($mntdrive,$outfile);



__END__

=head1 shimcacheprocess.pl

Image device

=head1 SYNOPSIS

shimcacheprocess.pl [options] [file ...]

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

B<shimcacheprocess.pl> is used for mass triage of system hives to pull out the shimcache.
=cut
