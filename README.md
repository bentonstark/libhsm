s
LIB-LUNA
=====================================

Project:	lib-luna
Artifact:	libluna.so
Author:		Benton Stark (benton.stark@gmail.com)
Date:		Nov 7, 2016
Purpose:	C/C++ shared library that can be compiled with g++/gcc on Linux 64-bit and Windows 64-bit using Visual Studio or g++/gcc.
		The library provide higher level language support for PKCS-11 API functions.   
			
		Contains no vendor proprietary code or 3rd party dependencies or APIs.
		Builds to OASIS PKCS#11 v2.20 open standard.


64-bit Linux Build:		
=========================================================
$ sudo yum install gcc-c++

$ cd ./build
$ ./build_libhsm

64-bit Linux Install:
=========================================================
$ sudo cp ./build/libluna.so /usr/lib64/libluna.so


			
