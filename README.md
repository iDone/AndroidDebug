# AndroidNdkDebugPlugin

		ADT now can be used to debug android so file in sourcecode mode, but still bugs and flaws
		Android Studio can be used to debug android project with jni code, by run ndk-debug configuration in "Edit Run/Debug Configuration"
		during the debugging, it will first compile so and apk files, then follows:

		  adb push 1.apk /data/local/tmp/1.apk
		  am start -D -n com.example.test/.MainActivity
		  waiting for app's status to be debuggable
		  set java-layer-breakpoints
		  adb push lldb_server 
		  ./lldb_server ..............setup lldb server
		  lldbfrontend.exe ........... connect to lldb server
		  send cmmand to lldb_server to attach to some pid
		  set jni-layer breakpoints 
		  remote connect to app and resume app running

		I cracked android-ndk.jar to make the process up there directly establish jni-layer debug, and finally it works!!!
		you can use the source code i cracked by follow steps:
		  export the eclipse project to android-ndk.jar
		  replace android-ndk.jar used by android studio, or install it as a plugin(must uninstall the origin), remember to bake up
		  restart android studio, open an existing android project with jni code
		  start app by hand, and make changes in "Run/Debug Configurations" in android studio, you shall see a process list
		  select the process you have just launched, press ok, and you will return to main window
		  press debug button, wait for a moment, you will see some info about attached to app
		  enjoy it!

		本插件为AndroidStudio插件
		背景：ADT已经开始支持jni模块源码调试，然而有一些未实现的部分。AndroidStudio自身支持启动方式调试jni，底层原理还是jdb+lldb方式；然而并未实现附加调试so源码。这样对于动态下发的so的源码级调试无能为力。本插件正是通过逆向并重新实现android-ndk.jar来实现调试动态下发so的源码的

		原始android-ndk.jar启动式调试jni得而实现步骤如下：
		  adb push 1.apk /data/local/tmp/1.apk
		  am start -D -n com.example.test/.MainActivity
		  等待app启动开启java调试线程
		  连接jdwp调试模块，下初始java断点
		  adb push lldb_server 
		  ./lldb_server ..............建立lldbserver用于调试jni层
		  lldbfrontend.exe ........... 建立client连接lldbserver
		  发送命令使lldb附加进程
		  设置jni初始断点
		  恢复java层和jni层执行，等待中断
		本插件正是对原始逻辑进行逆向，跳过之前的步骤从而直接连接到进程

		使用方式：
		1.编译android-ndk.jar，替换android studio自身的插件，重启as
		2.打开任意包含jni源码的app源码，在Run/Debug Configurations选项可以看到远程android进程列表，选择需要attach的进程
		3.运行进程即可，此时插件逻辑从启动进程改为附加进程，最终附加到app实现c++源码调试
	
# AndBugForWin
		AndBug是java层调试工具，封装了jdb利用python实现用户交互。因为jdb本身接口实在难用所以出现该工具。然而它不支持Windows甚至CygWin，因为AndBug中使用了*nix系统支持的localfilesystem监听方式而不是用socket端口监听方式，因此稍作修改即可实现win-cygwin上的同等功能

# superddms
		本插件用于修复ddms不识别本地android虚拟机的bug，android自带虚拟机的端口5037，而不同厂家的虚拟机采用不同端口
		
# superjdb
		关于jdwp的解析如我的这篇帖子：http://blog.csdn.net/lichao890427/article/details/51924451
		对于高版本的jdwp服务器端(如android5.0)，支持新的底层命令对字节码进行逐行调试；由于apk中一般去除了行号信息，因此jdb没有字节码的调试功能就像windbg没有反汇编单步步过一样扯淡，本插件实现了java字节码和dalvik字节码逐行调试，使用了java源码自带的jdb-gui
		
交流群560017652欢迎讨论
