# Porting duofs to the latest Linux kernel

## Introduction

duofs is a file system for persistent memory, developed by Intel.
For more details about duofs, please check the git repository:

https://github.com/linux-duofs/duofs

This project ports duofs to the latest Linux kernel so developers can compare duofs to other file systems on the new kernel.

## Building duofs
The master branch works on the 4.15 version of x86-64 Linux kernel.

To build duofs, simply run a

~~~
#make
~~~

command.

## Running duofs
duofs runs on a physically contiguous memory region that is not used by the Linux kernel, and relies on the kernel NVDIMM support.

To run duofs, first build up your kernel with NVDIMM support enabled (`CONFIG_BLK_DEV_PMEM`), and then you can
reserve the memory space by booting the kernel with `memmap` command line option.

For instance, adding `memmap=16G!8G` to the kernel boot parameters will reserve 16GB memory starting from 8GB address, and the kernel will create a `pmem0` block device under the `/dev` directory.

After the OS has booted, you can initialize a duofs instance with the following commands:


~~~
#insmod duofs.ko
#mount -t duofs -o init /dev/pmem0 /mnt/ramdisk 
~~~

The above commands create a duofs instance on pmem0 device, and mount on `/mnt/ramdisk`.

To recover an existing duofs instance, mount duofs without the init option, for example:

~~~
#mount -t duofs /dev/pmem0 /mnt/ramdisk 
~~~

There are two scripts provided in the source code, `setup-duofs.sh` and `remount-duofs.sh` to help setup duofs.

## Current limitations

* duofs only works on x86-64 kernels.
* duofs does not currently support extended attributes or ACL.
* duofs requires the underlying block device to support DAX (Direct Access) feature.
* This project cuts some features of the original duofs, such as memory protection and huge mmap support. If you need these features, please turn to the original duofs.
