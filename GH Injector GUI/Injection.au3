;FUNCTION LIST IN FILE ORDER:

;===================================================================================================
; Function........:  InjectDll($DllPath, $PID, $Is64BitProcess)
;
; Description.....:  Wrapperfunction to call the actual injector.
;
; Parameter(s)....:  $DllPath 			- A file handle or absolute path to the file.
;					 $PID				- The process identifier of the target process.
;					 $Is64BitProcess	- True if the process defined by $PID is a 64bit process
;===================================================================================================
; Function........:  Inject()
;
; Description.....:  Wrapperfunction to call the InjectDll function. Does some checks then forwards
;						all paths to the InjectDll function.
;===================================================================================================
; Function........:  PreInject()
;
; Description.....:  Verifies stuff and executes wait time before starting the injection process.
;
; Return Value(s).:  On Success - Returns true. Injection can continue.
;                    On Failure - Returns false. Injection can't continue.
;===================================================================================================

#include "GUI.au3"

#Region Global Definitions

Global $ToInject[32] = ["","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""]
Global $DllCount = 0

#EndRegion

Func InjectDll($DllPath, $PID, $Is64BitProcess)

	If ($Is64BitProcess = True) Then
		Run('"' & @ScriptDir & "\GH Injector - x64.exe" & '"' & " /p " & $PID & " /f " & '"' & $DllPath & '"' & " /m " & $g_InjectionMethod & " /o " & $g_InjectionFlags & " /l " & $g_LaunchMethod, "", @SW_HIDE)
	Else
		Run('"' & @ScriptDir & "\GH Injector - x86.exe" & '"' & " /p " & $PID & " /f " & '"' & $DllPath & '"' & " /m " & $g_InjectionMethod & " /o " & $g_InjectionFlags & " /l " & $g_LaunchMethod, "", @SW_HIDE)
	EndIf

EndFunc   ;==>InjectDll

Func Inject()

	Local $hK32 = DllOpen("kernel32.dll")
	If (@error OR ($hK32 = -1)) Then
		MsgBox($MB_ICONERROR, "Error", "Can't find kernel32.dll.")
		Return
	EndIf

	$hProc_info = DllCall($hK32, "HANDLE", "OpenProcess", _
		"DWORD", $PROCESS_QUERY_LIMITED_INFORMATION, _
		"INT", 0, _
		"DWORD", $g_PID _
	)

	If (NOT IsArray($hProc_info) OR ($hProc_info[0] = 0)) Then
		MsgBox($MB_ICONERROR, "Error", "Can't attach to process")
		$DllCount 			= 0
		$g_AutoInjection 	= False
		GUICtrlSetState($h_C_AutoI, $GUI_UNCHECKED)
		Return
	EndIf

	$x64 = Is64BitProcess($hProc_info[0])

	DllCall($hK32, "BOOL", "CloseHandle", _
		"HANDLE", $hProc_info[0] _
	)

	DllClose($hK32)

	For $i = 0 To $DllCount - 1 Step 1
		InjectDll(_GUICtrlListView_GetItemText($h_L_Dlls, $ToInject[$i], 2), $g_PID, $x64)
	Next

	For $i = 0 To $DllCount - 1 Step 1
		$Platform = _GUICtrlListView_GetItemText($h_L_Dlls, $ToInject[$i], 3)
		If ((StringCompare($Platform, "x64") AND $x64) OR (StringCompare($Platform, "x86") AND NOT $x64)) Then
			InjectDll(_GUICtrlListView_GetItemText($h_L_Dlls, $ToInject[$i], 2), $g_PID, $x64)
		EndIf
	Next

	$DllCount 			= 0

	If (NOT $g_CloseAfterInjection) Then
		$g_AutoInjection = False
		GUICtrlSetState($h_C_AutoI, $GUI_UNCHECKED)
	EndIf

	If ($g_CloseAfterInjection) Then
		SaveFiles($h_L_Dlls)
		SaveSettings()
		CloseGUI()
		Exit
	EndIf

EndFunc   ;==>Inject

Func PreInject()

	If (NOT ProcessExists(Number($g_PID))) Then
		If (NOT $g_AutoInjection) Then
			MsgBox($MB_ICONERROR, "Error", "Invalid target process specified.")
		EndIf
		Return False
	EndIf

	$Count = _GUICtrlListView_GetItemCount($h_L_Dlls)
	$DllCount = 0

	For $i = 0 To $Count - 1 Step 1
		If (_GUICtrlListView_GetItemChecked($h_L_Dlls, $i)) Then
			$ToInject[$DllCount] = $i
			$DllCount += 1
		EndIf

		If ($DllCount = 32) Then
			MsgBox($MB_ICONWARNING, "Warning", "Only up to 32 DLLs can be injected at once. The remaining DLLs won't be injected.")
			ExitLoop
		EndIf
	Next

	If (NOT $DllCount) Then
		If (NOT $g_AutoInjection) Then
			MsgBox($MB_ICONERROR, "Error", "No DLLs selected.")
		EndIf
		Return False
	EndIf

	Sleep($g_InjectionDelay)

	Return True
EndFunc   ;==>PreInject