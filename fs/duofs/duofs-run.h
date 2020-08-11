#!/bin/bash
WORKLOAD="/home/sekwon/strata/bench/filebench/rohan"
RESULTS="/home/sekwon/strata/bench/filebench/results"
FILEBENCH="/home/sekwon/filebench-rohan"

echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
sudo rm -rf /mnt/pmem_emul/*
sudo umount /mnt/pmem_emul
sudo insmod duofs.ko
sudo mount -t duofs -o init /dev/pmem0 /mnt/pmem_emul

#Fileserver
for i in {1..5}
do
    sudo ${FILEBENCH}/filebench -f ${WORKLOAD}/fileserver/fileserver${i}.f \
        >> ${RESULTS}/$1/duofs/file_${i}.txt
    sudo rm -rf /mnt/pmem_emul/*
    sudo umount /mnt/pmem_emul
    sudo mount -t duofs -o init /dev/pmem0 /mnt/pmem_emul
done

#Varmail
for i in {1..5}
do
    sudo ${FILEBENCH}/filebench -f ${WORKLOAD}/varmail/varmail${i}.f \
        >> ${RESULTS}/$1/duofs/var_${i}.txt
    sudo rm -rf /mnt/pmem_emul/*
    sudo umount /mnt/pmem_emul
    sudo mount -t duofs -o init /dev/pmem0 /mnt/pmem_emul
done

#Webserver_500
for i in {1..5}
do
    sudo ${FILEBENCH}/filebench -f ${WORKLOAD}/webserver/500/webserver${i}.f \
        >> ${RESULTS}/$1/duofs/web_500_${i}.txt
    sudo rm -rf /mnt/pmem_emul/*
    sudo umount /mnt/pmem_emul
    sudo mount -t duofs -o init /dev/pmem0 /mnt/pmem_emul
done

#Webserver_1000
#for i in {1..5}
#do
#    sudo ${FILEBENCH}/filebench -f ${WORKLOAD}/webserver/1000/webserver${i}.f \
#        >> ${RESULTS}/$1/duofs/web_1000_${i}.txt
#    sudo rm -rf /mnt/pmem_emul/*
#    sudo umount /mnt/pmem_emul
#    sudo mount -t duofs -o init /dev/pmem0 /mnt/pmem_emul
#done
