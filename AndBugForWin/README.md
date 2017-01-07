# AndBugForWin

As Is known to all, AndBug is a tool for debugging java/android application on Linux, while i modified Andbug for debugging on  Windows-Cygwin
Just Make it Easy to debug Android app, the usage is similiar to Linux :

  git clone
  
  make (for python 2.7 you need VS2008, and Microsoft Visual Studio 9.0\Common7\Tools in your %PATH% )
  
  modify andbug and add AndBug/lib to python syspath: mine is sys.path.append("/home/Administrator/tmp/AndBug/lib")
  
      'this script executes command modules found in andbug.commands'
    
      import os, os.path, sys, traceback, atexit
    
      sys.path.append("/home/Administrator/tmp/AndBug/lib")
    
  
  ./andbug
  
  
  
Administrator@WINWORK-UC7OSF4 ~/tmp/AndBug
$ make

python setup.py build_ext -i

running build_ext

building 'andbug.jdwp' extension

gcc -fno-strict-aliasing -ggdb -O2 -pipe -Wimplicit-function-declaration -fdebug-prefix-map=/usr/src/ports/python/python-2.7.10-1.i686/build=/usr/src/debug/python-2.7.10-1 -fdebug-prefix-map=/usr/src/ports/python/python-2.7.10-1.i686/src/Python-2.7.10=/usr/src/debug/python-2.7.10-1 -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -I/usr/include/python2.7 -c lib/jdwp/jdwp.c -o build/temp.cygwin-2.5.1-i686-2.7/lib/jdwp/jdwp.o

lib/jdwp/jdwp.c: 在函数‘__pyx_f_4jdwp_10JdwpBuffer_ipack’中:

lib/jdwp/jdwp.c:1405:3: 警告：隐式声明函数‘jdwp_expand’ [-Wimplicit-function-declaration]
   jdwp_expand((&((struct __pyx_obj_4jdwp_JdwpBuffer *)__pyx_v_self)->buf),__pyx_3);
   ^
   
gcc -fno-strict-aliasing -ggdb -O2 -pipe -Wimplicit-function-declaration -fdebug-prefix-map=/usr/src/ports/python/python-2.7.10-1.i686/build=/usr/src/debug/python-2.7.10-1 -fdebug-prefix-map=/usr/src/ports/python/python-2.7.10-1.i686/src/Python-2.7.10=/usr/src/debug/python-2.7.10-1 -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -I/usr/include/python2.7 -c lib/jdwp/wire.c -o build/temp.cygwin-2.5.1-i686-2.7/lib/jdwp/wire.o
lib/jdwp/wire.c:55:5: 警告：函数声明不是一个原型 [-Wstrict-prototypes]

 int checkCPUendian()
     ^
lib/jdwp/wire.c: 在函数‘htonll’中:
lib/jdwp/wire.c:82:25: 警告：隐式声明函数‘htonl’ [-Wimplicit-function-declaration]
     return (((uint64_t) htonl(val)) << 32) + htonl(val >> 32);
                         ^
                         
lib/jdwp/wire.c: 在函数‘ntohll’中:
lib/jdwp/wire.c:86:25: 警告：隐式声明函数‘ntohl’ [-Wimplicit-function-declaration]
     return (((uint64_t) ntohl(val)) << 32) + ntohl(val >> 32);
                         ^
                         
lib/jdwp/wire.c: 在函数‘jdwp_pack_u16’中:
lib/jdwp/wire.c:140:39: 警告：隐式声明函数‘htons’ [-Wimplicit-function-declaration]
  *(uint16_t*)(buf->data + buf->len) = htons(word);
                                       ^
                                       
lib/jdwp/wire.c: 在函数‘jdwp_unpack_u16’中:
lib/jdwp/wire.c:164:10: 警告：隐式声明函数‘ntohs’ [-Wimplicit-function-declaration]
  *word = ntohs(*(uint16_t*)(buf->data + buf->ofs));
          ^
          
gcc -shared -Wl,--enable-auto-image-base -L. build/temp.cygwin-2.5.1-i686-2.7/lib/jdwp/jdwp.o build/temp.cygwin-2.5.1-i686-2.7/lib/jdwp/wire.o -L/usr/lib/python2.7/config -L/usr/lib -lpython2.7 -o /home/Administrator/tmp/AndBug/lib/andbug/jdwp.dll

PYTHONPATH=lib python2 setup.py test

running test

.:: '' of () -> ''

:: '1' of (0,) -> '\x00'

:: '2' of (1,) -> '\x00\x01'

:: '4' of (1,) -> '\x00\x00\x00\x01'

:: '8' of (1,) -> '\x00\x00\x00\x00\x00\x00\x00\x01'

:: 'f' of (1,) -> '\x01'

:: 'm' of (1,) -> '\x00\x01'

:: 'o' of (1,) -> '\x00\x01'

:: 't' of (1,) -> '\x00\x00\x00\x01'

:: 's' of (1,) -> '\x00\x00\x00\x00\x00\x00\x00\x01'

:: '$' of ('abcd',) -> '\x00\x00\x00\x04abcd'

:: '1248' of (0, 1, 1, 1) -> '\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01'

:: 'fmots' of (0, 1, 1, 1, 1) -> '\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01'

.<<< 1 META
>>> 2 META
    00000000:  74 68 65 20 71 75 69 63 6b 20 62 72 6f 77 6e 20  the.quick.brown.
    00000010:  66 6f 78                                         fox
....
----------------------------------------------------------------------
Ran 6 tests in 0.014s

OK

#Administrator@WINWORK-UC7OSF4 ~/tmp/AndBug
$ ./andbug

## AndBug (C) 2011 Scott W. Dunlop <swdunlop@gmail.com>
   AndBug is a reverse-engineering debugger for the Android Dalvik virtual
   machine employing the Java Debug Wire Protocol (JDWP) to interact with
   Android applications without the need for source code.  The majority of
   AndBug's commands require the context of a connected Android device and a
   specific Android process to target, which should be specified using the -d
   and -p options.

   The debugger offers two modes -- interactive and noninteractive, and a
   comprehensive Python API for writing debugging scripts.  The interactive mode
   is accessed using:

   $ andbug shell [-d <device>] -p <process>.

   The device specification, if omitted, defaults in an identical fashion to the
   ADB debugging bridge command, which AndBug uses heavily.  The process
   specification is either the PID of the process to debug, or the name of the
   process, as found in "adb shell ps."

   AndBug is NOT intended for a piracy tool, or other illegal purposes, but  as
   a tool for researchers and developers to gain insight into the
   implementation of Android applications.  Use of AndBug is at your own risk,
   like most open source tools, and no guarantee of fitness or safety is made or
   implied.
## Options:
   -- -p, --pid <opt>
      the process to be debugged, by pid or name
   -- -d, --dev <opt>
      the device or emulator to be debugged (see adb)
   -- -s, --src <opt>
      adds a directory where .java or .smali files could be found
## Commands:
   -- class-trace | ct | ctrace <class-path>
      reports calls to dalvik methods associated with a class
   -- classes [<partial class name>]
      lists loaded classes. if no partial class name supplied, list all classes.
   -- dump <class-path> [<method-query>]
      dumps methods using original sources or apktool sources
   -- help [<command>]
      information about how to use andbug
   -- inspect <object-id>
      inspect an object
   -- methods <class-path> [<method-query>]
      lists the methods of a class
   -- shell
      starts the andbug shell with the specified process
   -- source <src-dir>
      adds a source directory for finding files
   -- statics <class-path>
      lists the methods of a class
   -- thread-trace | tt | ttrace <thread-name>
      reports calls to specific thread in the process
   -- threads [<name>] [verbose=<verbose level>]
      lists threads in the process. verbosity: 0 (thread), (1 methods), (2
      vars), (3 vars data)
   -- version | v
      Send version request.
## Examples:
   -- andbug classes -p com.ioactive.decoy
   -- andbug methods -p com.ioactive.decoy com.ioactive.decoy.DecoyActivity
      onInit

