#!/usr/bin/perl

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
use Fate;
use threads;
use threads::shared;

my $VERSION = 0.03;
#my $verbose = 1;

my $regripper="";
my $plugindir="";
my $regripperxp="";
my $regtime="";
my $regtime_human="";
my $regdump="";
my $savedirconfig="";
my $driveconfig="";
my $md5logfilename="";
my $config="";
my $maxthread = 10;  #10
my $num_threads = 0;

#=============================================================================================
# Get a list of plugins for RipXP
#=============================================================================================
sub ripxp_plugins {
	my @plugins;
	my $ntusercnt = 0;
	my $softwarecnt = 0;
	my $systemcnt = 0;
	my $securitycnt = 0;


	print "Reading in RegRipper plugin lists...    \n" if $verbose;
	print "\tReviewing plugins in directory: $plugindir\n" if $verbose;
	opendir(DIR,$plugindir) || die "Could not open RegRipper plugins directory @ $plugindir: $!\n";
	@plugins = grep {/\.pl$/}readdir(DIR);
	closedir(DIR);


	my $count = 1; 
	print "Plugin,Version,Hive,Description\n" if ($config{csv});
	foreach my $p (@plugins) {
		next unless ($p =~ m/\.pl$/);
		my $pkg = (split(/\./,$p,2))[0];
		$p = $plugindir.$p;
		#eval {
			require $p;
			my $hive    = $pkg->getHive();
			my $version = $pkg->getVersion();
			my $descr   = $pkg->getShortDescr();

		        #print $count.". ".$pkg." v.".$version." [".$hive."]\n";
			if ($hive eq "NTUSER.DAT") {
			   $ripxp_ntuser_plugins[$ntusercnt] = $pkg;
			   $ntusercnt++;
			}
			if ($hive eq "Software") {
			   $ripxp_software_plugins[$softwarecnt] = $pkg;
			   $softwarecnt++;
			}	
			if ($hive eq "System") {
			   $ripxp_system_plugins[$systemcnt] = $pkg;
			   $systemcnt++;
			}
			if ($hive eq "Security") {
			   $ripxp_ssecurity_plugins[$securitycnt] = $pkg;
			   $securitycnt++;
			}

		#};
		print "Error: $@\n" if ($@);
	}
	print "Done.\n" if $verbose;
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
	
	#Remove any double //
	$newfilename2 =~ s/\/\//\//;

	if ($doit == 1) {
	        print "\tCopying $cpfile to\n\t\t$newfilename2\n" if $verbose;
        	copy("$cpfile", "$newfilename2") or die "File cannot be copied: $! \"$cpfile\" to \"$newfilename2\"";

	        print "\tCalculating MD5 for $cpfile and\n\t\t$newfilename2\n" if $verbose;		
		my $md5 = md5file("$cpfile");
		my $md52 = md5file("$newfilename2");
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
# Create README file
#=============================================================================================
sub readme {
    my ($filename) = @_;
    open FILE, "> $filename";
    print FILE "README For Registry Plugin\n\n";

    print FILE "There are several different files that get created for each hive file found. Below is a\n";
    print FILE "short explaination of the output files.\n";
    print FILE "\tRegp Output = Output from the regdump.pl. Extension is regdump.log.\n";
    print FILE "\tRegripper Log = Straight output from regripper. Extension is regripper.log.\n";
    print FILE "\tRegripper Log Mactime = Output from regripper as mactimes. Extension is regripper.log.mactime.\n";
    print FILE "\tRegripper Log Mactime Bodyfile = Output from regripper as mactime bodyfile.\n";
    print FILE "\t                                 Extension is regripper.log.mactime.bodyfile.\n";
    print FILE "\tRegscan Log = This will show other deleted full keys and partial keys.\n";
    print FILE "\tLink file = Part of the process is to copy out the hive file and put it under\n";
    print FILE "\t            the output directory with the original path.\n";
    print FILE "\n\nMD5s\n";
    print FILE "The md5 for each hive file found is listed in md5log.md5\n";
    print FILE "\n\nFile name explaination\n";
    print FILE "Directory \/ or \\ have been replaced with a = in the filename.\n"; 
    print FILE "Example: Documents_and_Settings=Administrator=NTUSER.DAT\n";
    print FILE "Path and filename would look like: Documents_and_Settings\\Administrator\\NTUSER.DAT\n";    
    close FILE;
    return;
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
# Regripper Process the files
#=============================================================================================
sub regripperprocess {
    
  my ($file, $reglog, $regtype) = @_;

  $reglog .= ".regripper.log";
  print "\tLog file (regripper): $reglog\n"  if $verbose;
  my $error = `$regripper -r \"$file\" -f $regtype > $reglog 2> /dev/null`; 
  #print "ERROR REGRIPPER: $error = $regripper -r \"$file\" -f $regtype\n";
  my $error = `$regripper -r \"$file\" -f all >> $reglog 2> /dev/null`;    #Make sure to run the all category on the hive
  #print "ERROR REGRIPPER: $error = $regripper -r \"$file\" -f all\n";  
  return;
}
#=============================================================================================

#=============================================================================================
# Regdump Process the files
#=============================================================================================
sub regdumpprocess {
    
  my ($file, $reglog) = @_;

  $reglog .= ".regdump.log";
  print "\tLog file (regdump): $reglog\n"  if $verbose;
  my $error = `$regdump  \"$file\" > $reglog 2> /dev/null`;

  return;
}
#=============================================================================================

#=============================================================================================
# Regdump Process the files
#=============================================================================================
sub regscanprocess {
    
  my ($file, $reglog) = @_;

  $reglog .= ".regscan.log";
  print "\tLog file (regscan): $reglog\n"  if $verbose;
  my $error = `$regscan  \"$file\" > $reglog 2> /dev/null`;
  return;
}
#=============================================================================================

#=============================================================================================
# shimcacheprocess Process the files
#=============================================================================================
sub shimcacheprocess {
    
  my ($file, $reglog) = @_;

  $reglog .= ".shimcacheparser.log";
  print "\tLog file (regscan): $reglog\n"  if $verbose;
  my $error = `$shimcacheparser --reg \"$file\" > $reglog 2> /dev/null`;
  print "shimcache: $shimcacheparser --reg \"$file\" > $reglog 2> /dev/null\n" if $verbose;
  return;
}
#=============================================================================================

#=============================================================================================
# shellbagsparser Process the files
#=============================================================================================
sub shellbagsparser {
    
  my ($file, $reglog) = @_;

  $reglog .= ".shellbagsparser.log";
  print "\tLog file (regscan): $reglog\n"  if $verbose;
  my $error = `$shellbagsparser \"$file\" > $reglog 2> /dev/null`;
  print "shellbagsparser: $shellbagsparser  \"$file\" > $reglog 2> /dev/null\n" if $verbose;
  return;
}
#=============================================================================================

#=============================================================================================
# Regtime Process the files
#=============================================================================================
sub regtimeprocess {
    
  my ($file, $reglog, $type) = @_;

  my $reglogtime = $reglog.".mactime";
  my $reglogtime_human = $reglog.".regtime.txt.log";


  print "\tLog file (regtime): $reglogtime\n"  if $verbose;
  print "\tLog file (regtime2): $reglogtime_human\n"  if $verbose;
  my $error = `$regtime -m $type -r \"$file\" >> $reglogtime`;
  $error = `$regtime_human \"$file\" >> $reglogtime_human`;
  my $mactimelog = " > ".$reglog.".mactime.bodyfile";

  #my $flstext = $mactime . " -d -h -z ".$timezone." -b ".$reglogtime." ";
  my $flstext = $mactime . " -f \"$reglogtime\" > ".$reglogtime_human;
  #print "\tConverting mactime file to bodyfile using cmd: $flstext\n";
  $error = `$flstext`;
  return;
}
#=============================================================================================

#=============================================================================================
# Regdump Process the files
#=============================================================================================
sub regrestoreptprocess {
    
  my ($file,$reglog) = @_;
  $RP = $restorepts[$#restorepts];


  $reglog .= "_".$RP.".log";
  print "\tLog file (restore point): $reglog\n" if $verbose;

  foreach $plugin (@ripxp_ntuser_plugins) {
	  $error = `$regripperxp -r \"$file\" -d \"$dir/System Volume Information/$RP\" -p $plugin >> $reglog 2> /dev/null`;
	  $error = `echo \"==============================================================================================================\" >> $reglog `;
	  $error = `echo \"===     $plugin \" >> $reglog `;
	  $error = `echo \"==============================================================================================================\" >> $reglog `;
	  $error = `echo \" \" >> $reglog `;
  }
  return;
}
#=============================================================================================


#=============================================================================================
# Process the files
#=============================================================================================
sub threadprocess {


    $thread = threads->create(\&process);
    #process();
    @threadlist = threads->list(threads::running);
    $num_threads = $#threadlist;
    print "# of Threads: $num_threads\n" if $verbose;
    while($num_threads >= $maxthread) {
      print "Hit Thread MAX... Sleeping...\n";
      sleep(1);
      @threadlist = ();  #Need to destory the array and rebuild it to get a accurate count
      @threadlist = threads->list(threads::running);
      $num_threads = $#threadlist;
    }


}


#=============================================================================================
# Process the files
#=============================================================================================
sub process {

#    * ·        $_ contains the current filename within the directory
#    * ·        $File::Find::dir contains the current directory name
#    * ·        $File::Find::name contains $File::Find::dir/$_

     my $orglog = "";

     $srchfilename = lc($_);
     

      switch ($srchfilename) {
	  #case /ntuser.dat/ {
          case /ntuser/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      chomp($fileout);
	      my $reglog = "";
	      my $hash = "";
	      if ($fileout =~ /\bregistry\b/i) { 
		  print "\n\nWorking on $File::Find::name...   NTUSER Hive\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);


		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /log$/) {
		    } else {
		     if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "ntuser");
				regtimeprocess($File::Find::name, $orglog, "HKCU_USERNAME");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
				shellbagsparser($File::Find::name, $orglog);
			      } else {
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "ntuser");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_USERNAME");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&shellbagsparser,$File::Find::name, $orglog);
			  }
		      }
		  }
		  if ($systemvolsize > 0 ) {
		      if ($File::Find::name =~ /$restorepts[$#restorepts]/) {
		          if ($threadapp eq "n") {
				regrestoreptprocess($File::Find::name, $orglog)
			      } else {
				$thread = threads->create(\&regrestoreptprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }

	  }
	  #case /usrclass.dat/ {
          case /usrclass/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      chomp($fileout);
	      my $reglog = "";
	      my $hash = "";
	      if ($fileout =~ /\bregistry\b/i) { 
		  print "\n\nWorking on $File::Find::name...   UsrClass Hive\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);


		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /log$/) {
		    } else {
		     if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "usrclass");
				regtimeprocess($File::Find::name, $orglog, "UsrClass");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {         
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "usrclass");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "UsrClass");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
		  if ($systemvolsize > 0 ) {
		      if ($File::Find::name =~ /$restorepts[$#restorepts]/) {
		          if ($threadapp eq "n") {
				regrestoreptprocess($File::Find::name, $orglog)
			      } else {		      
				$thread = threads->create(\&regrestoreptprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }

	  }	  
	  case /systemprofile/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      chomp($fileout);
	      my $reglog = "";
	      my $hash = "";
	      if ($fileout =~ /\bregistry\b/i) { 
		  print "\n\nWorking on $File::Find::name...   SystemProfile Hive\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);
		  
		  print "\tProcessing $File::Find::name\n"  if $verbose;

		  if ($srchfilename =~ /log$/) {
		    } else {
		      if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "ntuser");
				regtimeprocess($File::Find::name, $orglog, "HKCU_USERNAME");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {         
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "ntuser");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_USERNAME");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
		  if ($systemvolsize > 0 ) {
		      if ($File::Find::name =~ /$restorepts[$#restorepts]/) {
		          if ($threadapp eq "n") {
				regrestoreptprocess($File::Find::name, $orglog)
			      } else {		      
				$thread = threads->create(\&regrestoreptprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }
	  }
	  case /default/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      #my ($filecmdpath,$filecmdout) = split(':',$fileout);
	      chomp($fileout);
	      my $reglog = "";
	      my $hash = "";
	      if ($fileout =~ /\bregistry\b/i) {
		  print "\n\nWorking on $File::Find::name...   Default Hive\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);

		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /log$/) {
		    } else { 
		      if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "default");
				regtimeprocess($File::Find::name, $orglog, "HKCU_DEFAULT");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {		         
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "default");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_DEFAULT");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }
	  }
	  case /sam/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      if ($fileout =~ m/registry/) {
		  print "\n\nWorking on $File::Find::name...  SAM File\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);

		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /log$/) {
		    } else {
		      if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "sam");
				regtimeprocess($File::Find::name, $orglog, "HKCU_SAM");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {         
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "sam");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_SAM");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }
	  }
	  case /security/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      if ($fileout =~ m/registry/) {
		  print "\n\nWorking on $File::Find::name...  Security File\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);

		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /log$/) {
		    } else {	
		    	if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "security");
				regtimeprocess($File::Find::name, $orglog, "HKCU_SECURITY");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "security");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_SECURITY");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }
	  }
	  case /software/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      if ($fileout =~ m/registry/) {
		  print "\n\nWorking on $File::Find::name...  Software File\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);

		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /log$/) {
		    } else {
		    if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "software");
				regtimeprocess($File::Find::name, $orglog, "HKCU_SOFTWARE");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {        
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "software");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_SOFTWARE");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
		  if ($systemvolsize > 0 ) {
		      if ($File::Find::name =~ /$restorepts[$#restorepts]/) {
		          if ($threadapp eq "n") {
				regrestoreptprocess($File::Find::name, $orglog)
			      } else {		      
				$thread = threads->create(\&regrestoreptprocess,$File::Find::name, $orglog);
			  }
		      }
		  }

	      }
	  }
	  case /system/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      if ($fileout =~ m/registry/) {
		  print "\n\nWorking on $File::Find::name...  System Hive\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);

		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /.log$/) {
		    } else {
		    if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "system");
				regtimeprocess($File::Find::name, $orglog, "HKCU_SYSTEM");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "system");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_SYSTEM");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&shimcacheprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
		  if ($systemvolsize > 0 ) {
		      if ($File::Find::name =~ /$restorepts[$#restorepts]/) {
		          if ($threadapp eq "n") {
				regrestoreptprocess($File::Find::name, $orglog)
			      } else {		      
				$thread = threads->create(\&regrestoreptprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }
	  }
	  case /userdiff/ {
	      my $fileout = `$filebin \"$File::Find::name\"`;
	      if ($fileout =~ m/registry/) {
		  print "\n\nWorking on $File::Find::name...  Userdiff Hive\n";
		  $orglog = copyfile($File::Find::dir,$File::Find::name,$_,1);

		  print "\tProcessing $File::Find::name\n"  if $verbose;
		  if ($srchfilename =~ /log$/) {
		    } else {
		    	if ($File::Find::dir =~ /snapshot/) {
		         } else {
		          if ($threadapp eq "n") {
				regripperprocess($File::Find::name, $orglog, "userdiff");
				regtimeprocess($File::Find::name, $orglog, "HKCU_USERDIFF");
				regdumpprocess($File::Find::name, $orglog);
				regscanprocess($File::Find::name, $orglog);
			      } else {		         
				$thread = threads->create(\&regripperprocess,$File::Find::name, $orglog, "userdiff");
				$thread = threads->create(\&regtimeprocess,$File::Find::name, $orglog, "HKCU_USERDIFF");
				$thread = threads->create(\&regdumpprocess,$File::Find::name, $orglog);
				$thread = threads->create(\&regscanprocess,$File::Find::name, $orglog);
			  }
		      }
		  }
	      }
	  }

	  else {}
      }
}
#=============================================================================================


GetOptions ("config=s"   => \$config,      # ini filename
	    "help|?"	 => \$help,
	    "man"	 => \$man, 
	    #"mntdrive=s"   => \$savedir,
	    "mntdrive=s"   => \$mntdrive,
	    "verbose"	 => \$verbose,	
           ) ||  pod2usage(2);
pod2usage(1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;

#=============================================================================================
# Read in config file
#=============================================================================================
if ($config eq ""){
  my($filename, $directories, $suffix) = fileparse(abs_path($0));
  $config = $directories."plugins.ini";
}

my $Config = Config::Tiny->read( $config );
if (defined $config) {
    $regripper=$Config->{regripper}->{regripper};
    $plugindir=$Config->{regripper}->{regripperplugins};
    $regripperxp=$Config->{regripper}->{regripperxp};
    $regtime=$Config->{regripper}->{regtime};
    $regtime_human=$Config->{regripper}->{regtime2};
    $regdump=$Config->{regripper}->{regdump};
    $regscan=$Config->{regripper}->{regscan};
    $savedirconfig=$Config->{regripper}->{savedir};
    $shimcacheparser=$Config->{regripper}->{shimcacheparser};
    $shellbagsparser=$Config->{regripper}->{shellbagsparser};
    $driveconfig=$Config->{default}->{drive};
    $timezone=$Config->{default}->{timezone};
    $mactime=$Config->{regripper}->{parse}; 
    $filebin=$Config->{default}->{filebin};
    #$parse=$Config->{regripper}->{parse};
    $threadapp=$Config->{regripper}->{thread};
  } else {
    print "Need a working config.ini file.\n";
    exit 1;
}
#=============================================================================================

my $dircwd = getcwd();
chomp($dircwd);

#=========================================================================
# Setup directory to search and save directory
#=========================================================================
$savedir = $dircwd . "/" . $savedirconfig;
$savedir = Fate::addslash($savedir);
$dir = Fate::workdir($mntdrive);
#=========================================================================

$md5logfilename =  $savedir . "md5log";
$readmefile = $savedir . "README.TXT";
print "Searching $dir for Registry files.\n";
print "Saving Registry files to: $savedir\n";
print "Using RegRipper Plugins in: $plugindir\n";
print "Config File Used: $config\n";
chdir($dir) or die "Cannot change directory to $dir -- Error: $!";

#Creating the save directory
unless(-e $savedir or mkdir $savedir) {
	die "Unable to create $savedir\n";
}

# Ensure the last character in $mntdrive has a slash at the end
#my $lastdirchr = substr $savedir,-1,1;
#if ($lastdirchr ne "\/") {
#   $savedir .= "\/"; 
#}

@ripxp_security_plugins = ();
@ripxp_ntuser_plugins = ();
@ripxp_software_plugins = ();
@ripxp_system_plugins = ();

ripxp_plugins();
print "Reading plugins for RipXP....\n" if $verbose;
print "\tUsing ".scalar(@ripxp_ntuser_plugins)." plugins for NTUSER.DAT.\n" if $verbose;
print "\tUsing ".scalar(@ripxp_software_plugins)." plugins for Software.\n" if $verbose;
print "\tUsing ".scalar(@ripxp_system_plugins)." plugins for System.\n" if $verbose;
print "\tUsing ".scalar(@ripxp_security_plugins)." plugins for Security.\n" if $verbose;

chdir("$dir/System Volume Information/");
my $rpcwd = getcwd;
print "\nChecking $rpcwd for Restore Points...\n" if $verbose;
my @systemvoldir = glob ("_restore*");
$systemvolsize = $#systemvoldir + 1;
@restorepts = ();
if ($systemvolsize > 0 ) {

    chdir("$dir/System Volume Information/$systemvoldir[0]");
    @restorepts = glob ("RP*");
    print "\tFound ".scalar(@restorepts)." Restore Points directories.\n" if $verbose;
    print "\tWill only process Restore Point: ".$restorepts[$#restorepts]."\n" if $verbose;
    print "Backing up System Volume Information (Restore Points)...\n";
    my $rpname = $savedir . "restorepoints_".$restorepts[$#restorepts].".tar.gz";
#    my $tarresults = `tar cvfz $rpname $restorepts[$#restorepts]`;   #----------------------------uncomment line
  } else {
    print "No Restore Points!!" if $verbose;
}
print "\n\n" if $verbose;

chdir('$dir'); 

if ($threadapp eq "n") {
    print "Working in non-threaded mode.\n";
    find(\&process, $dir);
   } else {
    print "Working in threaded mode.\n";
    find(\&threadprocess, $dir);

    while($num_threads != -1) {
      sleep(1);
      foreach $thr (threads->list) { 
	@threadlist = ();
	# Don't join the main thread or ourselves 
	if ($thr->tid && !threads::equal($thr, threads->self)) { 
	    $thr->join; 
	} 
      }
      @threadlist = threads->list;
      $num_threads = $#threadlist;
    }
}

print "\n\nCreating README file. Please review this for explaination on what is in the $savedir directory.\n";
readme($readmefile);



__END__

=head1 getreg.pl

Image device

=head1 SYNOPSIS

getreg.pl [options] 

Options:

--savedir     Directory to save files

--verbose     Verbose output

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

B<getreg.pl> will gather all of the registry files and run regripper on them.
=cut
