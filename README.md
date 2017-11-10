#libhsm
C/C++ shared library that can be compiled with g++/gcc on Linux 64-bit and Windows 64-bit using Visual Studio or g++/gcc.  The library provides a simplified API for access the PKCS#11 API to support higher level languages.  Compiles with OASIS PKCS#11 v2.20. 

## Supported HSMs
The libhsm library has been tested to work with the following HSMs.  Not all mechanisms are supported across the HSM vendors.
- SafeNet(Gemalto) Luna SA-5
- SafeNet(Gemalto) Luna PCIe K6 (6.2.1)
- SafeNet(Gemalto) Luna CA-4
- SafeNet(Gemalto) ProtectServer HSM PCIe
- Utimaco Security Server Simulator (SMOS Ver. 3.1.2.3)
- Utimaco CryptoServer PCIe
- Utimaco CryptoServer LAN (Se-Series Gen2)
- FutureX Vectera Plus (6.5.0.4-480B)
- Thales NShield Solo XC F3 High Speed 
- Cavium LiquidSecurity PCIe HSM (requires latest firmware Nov 2017)
- OpenDNSSEC SoftHSM 2.2.0
		
Note: Latest Cavium firmware requires CKA_DERIVE statements to be commented out from all templates.		
		
## CentOS Build	
```
$ sudo yum install gcc-c++
$ cd libhsm/build
$ ./build_libhsm
```

## CentOS Install
```
$ sudo cp libhsm/build/libhsm.so /usr/lib64/libhsm.so
```
	
## Header File Exports

https://github.com/bentonstark/libhsm/blob/master/src/p11hsm.h
