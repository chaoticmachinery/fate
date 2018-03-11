#!/bin/bash

#-------------------------------------------------------------------------
#  Description: Searches all Perl scripts for the use file and then
#               installs the Perl modules found.
#
#  Written By:  Keven Murphy
#  Version: 1.1
#  Date: 1/11/2013
#
#  License: GPL 2.0
#-------------------------------------------------------------------------

echo "Creating temporary file: perlmodules.txt"


#for PERLMOD in `find . -name "*.pl" -exec egrep "^use .*;$" {} \; | cut -d" " -f2 | sed "s/;//" | sort | uniq`
#do
#   echo 
#   echo "===================================================================================================="
#   echo "Installing $PERLMOD"
#   echo "===================================================================================================="
#   cpan $PERLMOD
#done
#
#for PERLMOD in `find . -name "*.pl" -exec egrep "^require .*;$" {} \; | cut -d" " -f2 | sed "s/;//" | sort | uniq`
#do
#   echo
#   echo "===================================================================================================="
#   echo "Installing $PERLMOD"
#   echo "===================================================================================================="
#   cpan $PERLMOD
#done

#Some modules require the following
cpan Module::Build



for FILE in `find . -exec file {} \; | grep Perl | cut -f 1 -d:  | sort | uniq`
do
   for PERLMOD in `egrep "^use .*;$" $FILE  | cut -d" " -f2 | sed "s/;//" | sort | uniq`
   do
       #echo
       #echo "===================================================================================================="
       #echo "Installing $PERLMOD"
       #echo "===================================================================================================="
       #cpan $PERLMOD
       echo "Found module: $PERLMOD"
       echo $PERLMOD  >> perlmodules.txt
   done
   for PERLMOD in `egrep "^require .*;$" $FILE  | cut -d" " -f2 | sed "s/;//" | sort | uniq`
   do
       #echo
       #echo "===================================================================================================="
       #echo "Installing $PERLMOD"
       #echo "===================================================================================================="
       #cpan $PERLMOD
       echo "Found module: $PERLMOD"
       echo $PERLMOD  >> perlmodules.txt
   done
done

for PERLMOD in `cat perlmodules.txt | sort | uniq`
do
       echo
       echo "===================================================================================================="
       echo "Installing $PERLMOD"
       echo "===================================================================================================="
       cpan $PERLMOD
done
