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
use Time::Local;
use DateTime;

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
# The procedures below are  copyright 2012 Quantum Analytics Research, LLC Author: H. Carvey keydet89@yahoo.com
#=============================================================================================
#---------------------------------------------------------
# parseJobHeader()
# 
#---------------------------------------------------------
sub parseJobHeader {
	my $data = shift;
	my %hdr;
#	my @vals = unpack("v16V5v8",$data);
	my @vals = unpack("v16V5",$data);
	
	$hdr{prod_ver} = $vals[0];
	$hdr{file_ver} = $vals[1];
# MS def of UUID: http://msdn.microsoft.com/en-us/library/cc232144%28PROT.13%29.aspx#universal_unique_identifier
	$hdr{app_name_offset} = $vals[10];
	$hdr{err_retry_int} = $vals[13];
	$hdr{exit_code} = $vals[18];
# Status codes: http://msdn.microsoft.com/en-us/library/aa383604%28VS.85%29.aspx
	$hdr{status} = $vals[19];
	
	
	my $datebytes = substr($data,0x34,16);
	($hdr{last_run_date}, $hdr{last_run_date_tz}) = parseDate128($datebytes);
	($hdr{last_run_date_as_epoch},$hdr{last_run_date_as_epoch_tz})= parseDate128AsEpoch($datebytes);
	
	return %hdr;
}

#---------------------------------------------------------
# parseDate128()
# $activetimebias
#---------------------------------------------------------
sub parseDate128 {
	my $date = $_[0];
	my @months = ("Jan","Feb","Mar","Apr","May","Jun","Jul",
	              "Aug","Sep","Oct","Nov","Dec");
	my @days = ("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
	my ($yr,$mon,$dow,$dom,$hr,$min,$sec,$ms) = unpack("v8",$date);
	my $dt = DateTime->new(
	    year       => $yr,
	    month      => $mon,
	    day        => 25,
	    hour       => $hr,
	    minute     => $min,
	    second     => $sec,
	    nanosecond => $ms,
	    time_zone  => 'America/Chicago',
	);
	if ($yr == 0) {
		return (0, 0);
	} else {
		$dt->add( hours => $activetimebias ); 
		$hr = "0".$hr if ($hr < 10);
		$min = "0".$min if ($min < 10);
		$sec = "0".$sec if ($sec < 10);
		my $str = $days[$dow]." ".$months[$mon - 1]." ".$dom." ".$hr.":".$min.":".$sec." ".$yr;
		return $str;
	}
}

#---------------------------------------------------------
# parseDate128AsEpoch()
# 
#---------------------------------------------------------
sub parseDate128AsEpoch {
	my $date = $_[0];
#	my @months = ("Jan","Feb","Mar","Apr","May","Jun","Jul",
#	              "Aug","Sep","Oct","Nov","Dec");
#	my @days = ("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
	my ($yr,$mon,$dow,$dom,$hr,$min,$sec,$ms) = unpack("v8",$date);
	
	if ($yr == 0) {
		return 0;
		
	}
	else {
# $time = timegm($sec,$min,$hour,$mday,$mon,$year);
		my $epoch = timegm($sec,$min,$hr,$dom,$mon,$yr);
                my $epoch_tz = timegm($sec,$min,$hr,$dom,$mon,$yr) - ($activetimebias * 60);
		return($epoch,$epoch_tz);
	}
}

sub jobparse {
    my @list;
    $taskdir = $taskdir."/" unless ($taskdir =~ m/\\$/);
    opendir(DIR,$taskdir) || die "Could not open ".$taskdir.": $!\n";
    @list = grep{/\.job$/} readdir(DIR);
    closedir(DIR);
    map {$files[$_] = $taskdir.$list[$_]}(0..scalar(@list) - 1);
	
    foreach my $file (@files) {
	    open(FH,"<",$file) || die "Could not open $file: $!\n";
	    binmode(FH);
	    seek(FH,0,0);
    # Read the header information
	    read(FH,$data,0x44);
	    my %hdr = parseJobHeader($data);

    # Running instance Count
	    seek(FH,0x44,0);
	    read(FH,$data,2);
	    $hdr{running_instance_count} = unpack("v",$data);

    # Read the appname
	    my $tag = 1;
	    my $ofs = 0;
	    while($tag) {
		    seek(FH,$hdr{app_name_offset} + $ofs,0);
		    read(FH,$data,2);
		    if (unpack("v",$data) == 0x00) {
			    $ofs += 2;
			    $tag = 0;
		    }
		    else {
			    $hdr{app_name} .= $data;
			    $ofs += 2;
		    }
	    }
	    $hdr{app_name} =~ s/\00//g;
    #printf "Offset = 0x%x\n",$hdr{app_name_offset} + $ofs;
    # Get Parameters
	    my $start = $hdr{app_name_offset} + $ofs;
	    my $tag = 1;
	    my $ofs = 0;
	    while ($tag) {
		    seek(FH,$start + $ofs,0);
		    read(FH,$data,2);
		    if (unpack("v",$data) == 0x00) {
			    $tag = 0;
		    }
		    else {
			    $hdr{parameters} .= $data;
			    $ofs += 2;
		    }
	    }
	    $hdr{parameters} =~ s/\00//g;
	    $hdr{parameters} =~ s/[[:cntrl:]]//g;

	    close(FH);

    #-----------------------------------------------------------
	    my %status = (0x00041300 => "Task is ready to run",
  	        	0x00041301 => "Task is running",
    	              0x00041302 => "Task is disabled",
      	            0x00041303 => "Task has not run",
        		  0x00041304 => "No more scheduled runs",
          		0x00041305 => "Properties not set",
            	      0x00041306 => "Last run terminated by user",
              	    0x00041307 => "No triggers/triggers disabled",
              	    0x00041308 => "Triggers do not have set run times");

	    if ($config{csv}) {
		    my $status;
		    if (exists $status{$hdr{status}}) {
			    $status = $status{$hdr{status}};
		    }
		    else {
			    $status = sprintf "0x%08x",$hdr{status};
		    }
		    print OUT $hdr{last_run_date}.",".$hdr{app_name}." ".$hdr{parameters}.",".$status."\n";
	    }
	    elsif ($config{tln}) {
		    my $descr = $hdr{app_name}." ".$hdr{parameters};
		    $descr .= "  Status: ".$status{$hdr{status}} if (exists $status{$hdr{status}});
		    my $str = $hdr{last_run_date_as_epoch}."|JOB|".$config{server}."||".$descr;
		    print OUT $str."\n";
	    }
	    else {
    #		$hdr{app_name} =~ s/\W//g;
		    print OUT "Command      : ".$hdr{app_name}." ".$hdr{parameters}."\n";
		    print OUT "Status       : ".$status{$hdr{status}}."\n" if (exists $status{$hdr{status}});

		    my $last_run;
		    if ($hdr{last_run_date_as_epoch} == 0) {
			    $last_run = "Never";
			    $last_run_tz = "Never";
		    }
		    else {
			    $last_run = $hdr{last_run_date};
			    $last_run_tz = $hdr{last_run_date_tz};
		    }

		    print OUT "Last Run Date (Local Time): ".$last_run."\n";
		    print OUT "Last Run Date (".$timezone."): \n";
		    printf OUT "Exit Code    : 0x%x\n",$hdr{exit_code};
		    print OUT "\n";
	    }
    }	

}
#=============================================================================================

#=============================================================================================
# process
#=============================================================================================
sub processtasks {
    #my ($path) = @_;

#    * �        $_ contains the current filename within the directory
#    * �        $File::Find::dir contains the current directory name
#    * �        $File::Find::name contains $File::Find::dir/$_
    #my $windir = "";
    $srchfilename = lc($_);
    #Need to find SAM hive to make sure we have the Windows directory
    if ($srchfilename =~ /job$/i) {
       $windirtemp = $File::Find::dir;
       if ($windirtemp =~ /tasks/i) {
	  $taskdir = $File::Find::dir;
       }
    }

}
#=============================================================================================

#=============================================================================================
# process for Timezone
#=============================================================================================
sub processtimezone {
    #my ($path) = @_;

#    * �        $_ contains the current filename within the directory
#    * �        $File::Find::dir contains the current directory name
#    * �        $File::Find::name contains $File::Find::dir/$_
    #my $windir = "";   /appl/regripper3/rip.pl -r WINNT=system32=config=System -p timezone

    if ($fndactivetimebias < 0) {
    
	$srchfilename = lc($_);
	
	#Need to find SAM hive to make sure we have the Windows directory
	if ($srchfilename eq "system") {
	    my $fileout = `file \"$File::Find::name\"`;
	    my @dirlist = split(/\//, $File::Find::dir);
	    #for ($cnt = 0; $cnt <= $#dirlist; $cnt++) {
	    #}
	    
	    if ($dirlist[$#dirlist - 1] =~ /config/i) {
		if ($dirlist[$#dirlist - 2] =~ /system32/i) {
		    print "1: $dirlist[$#dirlist - 1] -- 2: $dirlist[$#dirlist - 2]\n\n";
		    if ($fileout =~ m/registry/) {
			$activetimebias = `$regripper -r $File::Find::name -p timezone | grep ActiveTimeBias  | grep hours | cut -d\\( -f2 |cut -d\" \" -f 1  2> /dev/null`;
			$fndactivetimebias++;
			print "L: $regripper -r $File::Find::name -p timezone | grep ActiveTimeBias  | grep hours | cut -d\\( -f2 |cut -d\" \" -f 1  2> /dev/null \n";
		    }
		}
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
    $savedirconfig=$Config->{jobparse}->{savedir};
    $driveconfig=$Config->{default}->{drive};
    $timezone=$Config->{default}->{timezone};
    $regripper=$Config->{regripper}->{regripper};
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

$savedir = $dircwd . "/" . $savedirconfig;
$dir = $dircwd;
$md5logfilename =  $savedir . "/md5log";
print "Searching $dir for job files.\n";
print "Saving job files to: $savedir\n";
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

$savedir = addslash($savedir);
$outfile = $savedir . "jobparse.txt";
open (OUT, "> $outfile");
print OUT "Job Parse\n\n";


print "Searching for the Tasks directory.... ";
find(\&processtasks, $dir);
print "Found.\n";
print "Searching for the System Hive for timezone information.... ";
find(\&processtimezone, $dir);
print "Found.\n";
print OUT "ActiveTimeBias: $activetimebias\n\n";

print "Processing job files.... ";

jobparse();
print "Done.\n";

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
