#!/bin/sh

PART=`awk '/NTFS/ {print $3}'  *mmls  | sed -e  's/^[0]*//'`
echo "NTFS partition found at: $PART"
DDFILE=`pwd`/*.dd
MNTPATH=`pwd`/drive

mount -t ntfs-3g -o loop,ro,nodev,noatime,show_sys_files,streams_interface=windows,offset=`echo $(( $PART * 512 ))`  $DDFILE $MNTPATH
