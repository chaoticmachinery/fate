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

$version = 0.01;

#=============================================================================================
# MFT Code by Mr. Carvey 
# Altered for use as a plugin
#=============================================================================================
#-----------------------------------------------------------
# parse $MFT; to use, pass the path to an $MFT to the script
# as an arguement:
#
# mft.pl D:\cases\case1\$mft > mft.txt
#
# Ref:
#    http://msdn.microsoft.com/en-us/library/bb470206%28VS.85%29.aspx
#
# copyright 2011-2012 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------

sub mft {
    #my $file = shift || die "You must enter a filename.\n";
    my ($file,$savedir) = @_;
    die "Could not find $file\n" unless (-e $file);

    my %attr_types = (16 => "Standard Information",
		    48 => "File name",
		    64 => "Object ID",
		    128 => "Data",
		    144 => "Index Root",
		    160 => "Index Allocation",
		    176 => "Bitmap");

    #-----------------------------------------------------------
    # Flags from MFT entry header (use an AND/& operation)
    #    00 00 deleted file
    #    01 00 allocated file
    #    02 00 deleted directory
    #    03 00 allocated directory
    #-----------------------------------------------------------

    my $count = 0;
    my $size = (stat($file))[7];
    my $data;
    my %mft;

    my $outfilename = $savedir."/mft.txt";
    my $csvoutfilename = $savedir."/mft.csv"; 
    open(OUT,">",$outfilename) || die "Could not open $file to write: $!\n";
    open(CSVOUT,">",$csvoutfilename) || die "Could not open $file to write: $!\n";

    open(MFT,"<",$file) || die "Could not open $file to read: $!\n";
    binmode(MFT);
    
    print CSVOUT "Filename,Standard M,Standard A,Standard C,Standard B, FileName M, FileName A, Filename C, Filename B\n";
    
    while(($count * 1024) < $size) {
	  seek(MFT,$count * 1024,0);
	  read(MFT,$data,1024);
	  
	  my $hdr = substr($data,0,42);
	  $mft{sig} = unpack("A4",substr($hdr,0,4));
	  $mft{seq} = unpack("v",substr($hdr,16,2));
	  $mft{linkcount} = unpack("v",substr($hdr,18,2));
	  $mft{attr_ofs} = unpack("v",substr($hdr,20,2));
	  $mft{flags} = unpack("v",substr($hdr,22,2));
	  $mft{next_attr_id} = unpack("v",substr($hdr,40,2));

    # using flags, run an AND operation (ie, &) with flags
    #  if ($mft{flags} & 0x0001) - allocated; else unallocated/deleted
    #	 if ($mft{flags} & 0x0002) - folder/dir; else file	           
	  printf OUT "%-10d %-4s Seq: %-4d Link: %-4d 0x%02x %-4d  Flags: %-4d\n", $count,$mft{sig},$mft{seq},$mft{linkcount},$mft{attr_ofs},$mft{next_attr_id},$mft{flags};
	  printf CSVOUT "%-10d,%-4s Seq: %-4d,Link: %-4d,0x%02x %-4d,Flags: %-4d,", $count,$mft{sig},$mft{seq},$mft{linkcount},$mft{attr_ofs},$mft{next_attr_id},$mft{flags};
	  		  
	  $count++;
	  next unless ($mft{sig} eq "FILE");
	  
	  my $ofs = $mft{attr_ofs};
	  my $next = 1;
	  
	  while ($next == 1) {
		  my $attr = substr($data,$ofs,16);
		  my ($type,$len,$res,$name_len,$name_ofs,$flags,$id) = unpack("VVCCvvv",$attr);
		  $next = 0 if ($type == 0xffffffff || $type == 0x0000);
		  printf OUT "  0x%04x %-4d %-2d  0x%04x 	0x%04x\n",$type,$len,$res,$name_len,$name_ofs unless ($type == 0xffffffff);
    # $SIA is always resident, so the extra check doesn't matter
		  if ($type == 0x10 && $res == 0) {
			  my %si = parseSIAttr(substr($data,$ofs,$len));			
			  print OUT "    M: ".gmtime($si{m_time})." Z\n";
			  print OUT "    A: ".gmtime($si{a_time})." Z\n";
			  print OUT "    C: ".gmtime($si{mft_m_time})." Z\n";
			  print OUT "    B: ".gmtime($si{c_time})." Z\n";
			  print CSVOUT $fn{name}.",";
			  print CSVOUT gmtime($si{m_time})." Z,";
			  print CSVOUT gmtime($si{a_time})." Z,";
			  print CSVOUT gmtime($si{mft_m_time})." Z,";
			  print CSVOUT gmtime($si{c_time})." Z,";			  
		  }
    # $FNA is always resident, so the extra check doesn't matter
		  elsif ($type == 0x30 && $res == 0) {
			  my %fn = parseFNAttr(substr($data,$ofs,$len));
			  print OUT "  FN: ".$fn{name}."  Parent Ref: ".$fn{parent_ref}."  Parent Seq: ".$fn{parent_seq}."\n";
			  print OUT "    M: ".gmtime($fn{m_time})." Z\n";
			  print OUT "    A: ".gmtime($fn{a_time})." Z\n";
			  print OUT "    C: ".gmtime($fn{mft_m_time})." Z\n";
			  print OUT "    B: ".gmtime($fn{c_time})." Z\n";
			  print CSVOUT gmtime($fn{m_time})." Z,";
			  print CSVOUT gmtime($fn{a_time})." Z,";
			  print CSVOUT gmtime($fn{mft_m_time})." Z,";
			  print CSVOUT gmtime($fn{c_time})." Z\n";			  
		  }
    # This is where other attributes would get handled
		  else{}		
		  $ofs += $len;
	  }
	  print OUT "\n";
	  print CSVOUT "\n";
    #	$count++;
    }
    close(MFT);
    close(CSVOUT);
    close(OUT);

    sub parseSIAttr {
	  my $si = shift;
	  my %si;
	  my ($type,$len,$res,$name_len,$name_ofs,$flags,$id,$sz_content,$ofs_content) 
		  = unpack("VVCCvvvVv",substr($si,0,22));
		  
	  my $content = substr($si,$ofs_content,$sz_content);
	  my ($t0,$t1) = unpack("VV",substr($content,0,8));
	  $si{c_time} = getTime($t0,$t1);
	  my ($t0,$t1) = unpack("VV",substr($content,8,8));
	  $si{m_time} = getTime($t0,$t1);
	  my ($t0,$t1) = unpack("VV",substr($content,16,8));
	  $si{mft_m_time} = getTime($t0,$t1);
	  my ($t0,$t1) = unpack("VV",substr($content,24,8));
	  $si{a_time} = getTime($t0,$t1);
	  $si{flags} = unpack("V",substr($content,32,4));	
		  
	  return %si;	
    }


    sub parseFNAttr {
	  my $fn = shift;
	  my %fn;
	  my ($type,$len,$res,$name_len,$name_ofs,$flags,$id,$sz_content,$ofs_content) 
		  = unpack("VVCCvvvVv",substr($fn,0,22));
	  
	  my $content = substr($fn,$ofs_content,$sz_content);
	  $fn{parent_ref} = unpack("V",substr($content,0,4));
	  $fn{parent_seq} = unpack("v",substr($content,6,2));
	  my ($t0,$t1) = unpack("VV",substr($content,8,8));
	  $fn{c_time} = getTime($t0,$t1);
	  my ($t0,$t1) = unpack("VV",substr($content,16,8));
	  $fn{m_time} = getTime($t0,$t1);
	  my ($t0,$t1) = unpack("VV",substr($content,24,8));
	  $fn{mft_m_time} = getTime($t0,$t1);
	  my ($t0,$t1) = unpack("VV",substr($content,32,8));
	  $fn{a_time} = getTime($t0,$t1);
	  
	  $fn{flags} = unpack("V",substr($content,56,4));
	  
	  $fn{len_name} = unpack("C",substr($content,64,1));
	  $fn{namespace} = unpack("C",substr($content,65,1));
	  $fn{len_name} = $fn{len_name} * 2 if ($fn{namespace} > 0);
	  $fn{name} = substr($content,66,$fn{len_name});
	  $fn{name} = cleanStr($fn{name}) if ($fn{namespace} > 0);
	  $fn{name} =~ s/\x0c/\x2e/g;
	  $fn{name} =~ s/[\x01-\x0f]//g;
    #	$fn{name} = decode("UTF-8",$fn{name}) if ($fn{namespace} > 0);
    #	$fn{name} =~ s/\00//g;
	  
	  return %fn;
    }

    #-------------------------------------------------------------
    # cleanStr()
    # 'Clean up' Unicode strings; in short, 
    #-------------------------------------------------------------
    sub cleanStr {
	  my $str = shift;
	  my @list = split(//,$str);
	  my @t;
	  my $count = scalar(@list)/2;
	  foreach my $i (0..$count) {
		  push(@t,$list[$i*2]);
	  }
	  return join('',@t);
    }

    #-------------------------------------------------------------
    # getTime()
    # Translate FILETIME object (2 DWORDS) to Unix time, to be passed
    # to gmtime() or localtime()
    #-------------------------------------------------------------
    sub getTime($$) {
	  my $lo = shift;
	  my $hi = shift;
	  my $t;

	  if ($lo == 0 && $hi == 0) {
		  $t = 0;
	  } else {
		  $lo -= 0xd53e8000;
		  $hi -= 0x019db1de;
		  $t = int($hi*429.4967296 + $lo/1e7);
	  };
	  $t = 0 if ($t < 0);
	  return $t;
    }

}
#=============================================================================================


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
    $savedirconfig=$Config->{MFT}->{savedir};
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
$dir = $dircwd;
$mftfilename = $dir."/\$MFT";
$md5logfilename =  $savedir . "/md5log";
print "Reviewing $mftfilename MFT file.\n";
print "Saving MFT output file to: $savedir\n";
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




#Need to determin OS
my $OS = `uname -s`;

if ($OS =~ /Linux/) {
     $mftfile = $dir."\$MFT";
     mft($mftfilename,$savedir);
   } else {
     print "\nMFT plugin does not work with OSX.\n";
}







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
