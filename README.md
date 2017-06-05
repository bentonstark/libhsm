#libhsm
C/C++ shared library that can be compiled with g++/gcc on Linux 64-bit and Windows 64-bit using Visual Studio or g++/gcc.  The library provides a simplified API for access the PKCS#11 API to support higher level languages.  Compiles with OASIS PKCS#11 v2.20. 

## Supported HSMs
The libhsm library works with the following HSM devices and software based HSMs.
- SafeNet / Gemalto Luna SA-4
- SafeNet / Gemalto Luna SA-5
- SafeNet / Gemalto Luna PCIe K5/K6
- SafeNet / Gemalto Luna CA-4
- SafeNet ProtectServer HSM PCIe
- Utimaco Security Server Simulator (SMOS Ver. 3.1.2.3)
- OpenDNSSEC SoftHSM 2.2.0
		
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
