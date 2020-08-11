#!/bin/sh

umount /mnt/ramdisk
rmmod duofs
insmod duofs.ko measure_timing=0

sleep 1

#mount -t duofs -o physaddr=0x100000000 none /mnt/ramdisk
mount -t duofs -o physaddr=0x10000000000 none /mnt/ramdisk

#cp test1 /mnt/ramdisk/
#dd if=/dev/zero of=/mnt/ramdisk/test1 bs=1M count=1024 oflag=direct
