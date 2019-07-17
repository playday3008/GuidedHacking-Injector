# GuidedHacking-Injector
Fully Featured DLL Injector made by Broihon

Release Downloads: https://guidedhacking.com/resources/guided-hacking-dll-injector.4/

https://i.gyazo.com/8cd3bc29780384752e0ace773f472e62.png

Injection Methods:
-LoadLibrary
-LdrLoadDll Stub
-Manual Mapping

Launch Methods:
-NtCreateThreadEx
-Thread Hijacking
-SetWindowsHookEx
-QueueUserAPC

Compatible with both 32-bit and 64-bit programs running on Windows XP or higher. 
Settings of the GUI are saved to a local ini file.  Processes can be 
selected by name or process ID and by the fancy process picker.

Since GH Injector V3.0 the actual injector has been converted in to a library

To use it in your applications you can either use InjectA (ansi) or 
InjectW (unicode) which are the two functions exported by the "GH 
Injector - x86.dll"/"GH Injector - x64.dll". These functions take a 
pointer to a INJECTIONDATAA/INJECTIONDATAW structure. For more the 
struct definition / enums / flags check "Injection.h".

Rake's dank video tutorial for v2.4 showing how to use it's features and a source code review:

[MEDIA=youtube]zhA9kSCY3Ec:7[/MEDIA]

Credits
For the Manual Mapping a lot of credits go to Joachim Bauch. You can visit his website here.
I highly recommend you to go there and take a look if you're interested in Manual Mapping and the PE format itself.
The windows structures I use for the unlinking process are mostly inspired by this site which is also a very interesting read.  I also want to credit Anton Bruckner and Dmitri Shostakovich
 because most of the time coding this I listened to their fantastic 
music which is probably one of the reasons why this took me way too long


