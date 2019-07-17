rd "GH Injector" /q /s
mkdir "GH Injector"

copy "GH Injector GUI\GH Injector - x64.exe" "GH Injector" /y
copy "GH Injector GUI\GH Injector - x86.exe" "GH Injector" /y
copy "GH Injector GUI\GH Injector.exe" "GH Injector" /y

copy "GH Injector Library\Release\x64\GH Injector - x64.dll" "GH Injector" /y
copy "GH Injector Library\Release\x86\GH Injector - x86.dll" "GH Injector" /y
copy "GH Injector Library\Release\x64\GH Injector SWHEX - x64.exe" "GH Injector" /y
copy "GH Injector Library\Release\x86\GH Injector SWHEX - x86.exe" "GH Injector" /y