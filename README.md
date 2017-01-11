#libhsm
C/C++ shared library that can be compiled with g++/gcc on Linux 64-bit and Windows 64-bit using Visual Studio or g++/gcc.  The library provides a simplied API for access the PKCS#11 API to support higher level languages.  Compiles with OASIS PKCS#11 v2.20. 
		
## CentOS Build	
```
$ sudo yum install gcc-c++
$ cd ./build
$ ./build_libhsm
```

## CentOS Install
```
$ sudo cp ./build/libhsm.so /usr/lib64/libhsm.so
```

			
