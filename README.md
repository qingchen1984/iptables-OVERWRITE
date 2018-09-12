# iptables-OVERWRITE 

This is a combination of an iptables extension as well as a corresponding netfilter extension using the xtables framework. This extension allows the user to arbitrarily overwrite any data in an IP packet. Originally designed for breaking covert channels like ICMP tunnels.

### Prerequisites

pkg-config
libtool
autoconf
make
automake
iptables source code: [https://www.netfilter.org/projects/iptables/files/iptables-1.6.2.tar.bz2](https://www.netfilter.org/projects/iptables/files/iptables-1.6.2.tar.bz2)

```
sudo apt install pkg-config libtool autoconf make automake
wget https://www.netfilter.org/projects/iptables/files/iptables-1.6.2.tar.bz2
tar -xvf iptables-1.6.2.tar.bz2 
```

### Installing

1) Download this repository along with the iptables source directory 

```
git clone https://github.com/SecurityInnovation/iptables-OVERWRITE.git
```

2) Change directory to this repository
```
cd iptables-OVERWRITE
```

3) Configure, compile and insert the kernel module
```
cd kernel
make
make install
```

3.5) _If the above didnt work_ then you make need to stop some services that depend on the x\_tables kernel module
```
sudo service ebtables stop
```

4) Copy the necessary files to the iptables directory
```
cd ..
cp ./ipt_OVERWRITE.h ../iptables-1.6.2/include/linux/netfilter_ipv4/ipt_OVERWRITE.h
cp ./iptables/libipt_OVERWRITE.c ../iptables-1.6.2/extensions/
```

5) Change directory to the iptables directory, build, and install it
```
cd ../iptables-1.6.2/
./autogen.sh
./configure --disable-nftables
make
sudo make install
```

Note that you may have to restart bash to use the version of iptables you just installed

## Usage
OVERWRITE target options
```
--overwrite-str <string>                 overwrite section of packet with string
--overwrite-hex <hex string>             overwrite section by repeating string
--offset <value 0-65535>                 offset from beginning of ip packet to start writing
--offload                                offloads checksum processing of some checksums to NIC
                                         by default the extension processes all checksums internally
```
Examples
```
//on output, if udp, overwrite the 50th byte of the ip packet with "a"
iptables -A OUTPUT -t mangle -p udp -j OVERWRITE --offset 50 --overwrite-str "a"
//on output, if udp, overwrite the 60th byte of the ip packet with a null byte, 
//also offloads checksum calculation to the NIC (faster, but may not be supported)
iptables -A OUTPUT - mangle -p udp -j OVERWRITE --offset 60 --overwrite-hex "00" --offload
```

## License
This project is licensed under the GPL License

## Acknowledgments

* Tom Samstag for all the help with programming in C
* rootfoo, for teaching me how to build kernel modules
* Thanks to the National Collegiate Cyber Defense Competion for the inspiration
* Security Innovation for the oppurtunity to build this tool


