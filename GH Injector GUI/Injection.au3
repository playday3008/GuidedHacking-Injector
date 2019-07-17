;FUNCTION LIST IN FILE ORDER:

;===================================================================================================
; Function........:  InjectDll($DllPath, $PID)
;
; Description.....:  Calls the InjectW function in the injection library.
;
; Parameter(s)....:  $DllPath 	- The absolute path to the file.
;					 $PID		- The process identifier of the target process.
;===================================================================================================
; Function........:  Inject($hMainGUI)
;
; Parameter(s)....:  $hMainGUI	- A handle to the main GUI to create the injection GUI on.
;
; Description.....:  Wrapperfunction to call the InjectDll function. Does some checks then forwards
;						each path to the InjectDll function.
;===================================================================================================
; Function........:  PreInject()
;
; Description.....:  Verifies stuff and executes delay before starting the injection process.
;
; Return Value(s).:  On Success - Returns true. Injection can continue.
;                    On Failure - Returns false. Injection can't continue.
;===================================================================================================
#include "GUI.au3"

#Region Global Definitions

Global $hInjectionDll = 0


$h_InjectionGUI = 0
$h_ProgressBar 	= 0
$h_LabelGUI		= 0
$h_Label		= 0

Global Const $INJECTIONDATAW = _
	"struct;							" & _
		"DWORD 		LastErrorCode;		" & _
		"WCHAR		szDllPath[520];		" & _
		"DWORD 		ProcessId;			" & _
		"DWORD 		InjectionMode;		" & _
		"DWORD 		LaunchMethod;		" & _
		"DWORD 		Flags;				" & _
		"DWORD		hHandleValue;		" & _
		"PTR	 	hDllOut;			" & _
	"endstruct							"

#EndRegion

Func InjectDll($DllPath, $PID)

	$Data 	= DllStructCreate($INJECTIONDATAW)
	$pData 	= DllStructGetPtr($Data)

	$Data.ProcessId 		= $PID
	$Data.szDllPath			= $DllPath
	$Data.InjectionMode 	= $g_InjectionMethod
	$Data.LaunchMethod		= $g_LaunchMethod
	$Data.Flags				= $g_InjectionFlags
	$Data.LastErrorCode		= 0
	$Data.hHandleValue		= 0
	$Data.hDllOut			= 0

	Local $dllRet = DllCall($hInjectionDll, _
		"DWORD", "InjectW", _
			"STRUCT*", $pData _
	)
	If (IsArray($dllRet)) Then
		If ($dllRet[0] <> 0) Then
			MsgBox($MB_ICONERROR, "Error 0x" & StringFormat("%08X", $dllRet[0]), "An error has occurred. For more information check this file:" & @CRLF & @ScriptDir & "\GH_Inj_Log.txt")
		EndIf
	Else
		MsgBox($MB_ICONERROR, "Error " & @error, "Can't call InjectW.")
	EndIf

EndFunc   ;==>InjectDll


Func Inject()

	$DllCount = _GUICtrlListView_GetItemCount($h_L_Dlls)

	If ($DllCount <> 0) Then

		For $i = 0 To $DllCount - 1 Step 1
			$Arch = _GUICtrlListView_GetItemText($h_L_Dlls, $i, 3)
			If ($Arch = $l_TargetProcessArchitecture OR ($l_TargetProcessArchitecture = "---" AND BitAND($g_InjectionFlags, $INJ_HIJACK_HANDLE))) Then
				InjectDll(_GUICtrlListView_GetItemText($h_L_Dlls, $i, 2), $g_PID)
			EndIf

			GUICtrlSetData($h_ProgressBar, Ceiling((100 / $DllCount) * $i) + 5)
		Next

		GUISetState(@SW_HIDE, $h_LabelGUI)
		GUIDelete($h_LabelGUI)
		GUISetState(@SW_HIDE, $h_InjectionGUI)
		GUIDelete($h_InjectionGUI)

		If (NOT $g_CloseAfterInjection) Then
			$g_AutoInjection = False
			GUICtrlSetState($h_C_AutoI, $GUI_UNCHECKED)
		EndIf

		If ($g_CloseAfterInjection) Then
			Return $GUI_CLOSE
		EndIf
	EndIf

	Return $GUI_RETURN

EndFunc   ;==>Inject

Func PreInject($hMainGUI)

	If (NOT ProcessExists(Number($g_PID))) Then
		If (NOT $g_AutoInjection) Then
			MsgBox($MB_ICONERROR, "Error", "Invalid target process specified.")
		EndIf
		Return False
	EndIf

	$bDllSelected = False
	$Count = _GUICtrlListView_GetItemCount($h_L_Dlls)
	For $i = 0 To $Count - 1 Step 1
		If (_GUICtrlListView_GetItemChecked($h_L_Dlls, $i)) Then
			If (_GUICtrlListView_GetItemText($h_L_Dlls, $i, 3) = $l_TargetProcessArchitecture OR ($l_TargetProcessArchitecture = "---" AND BitAND($g_InjectionFlags, $INJ_HIJACK_HANDLE))) Then
				$bDllSelected = True
				ExitLoop
			EndIf
		EndIf
	Next

	If (NOT $bDllSelected) Then
		If (NOT $g_AutoInjection) Then
			MsgBox($MB_ICONERROR, "Error", "No valid DLL selected.")
		EndIf
		Return False
	EndIf

	Local $size = WinGetClientSize($hMainGUI)
	$h_InjectionGUI = GUICreate("", 200, 100, $size[0] / 2 - 100, $size[1] / 2 - 50, $WS_POPUP, BitOR($WS_EX_TOPMOST, $WS_EX_MDICHILD), $hMainGUI)
	$h_ProgressBar 	= GUICtrlCreateProgress(5, 5, 190, 90)
	GUICtrlSetData($h_ProgressBar, 1)

	$h_LabelGUI = GUICreate("", 200, 100, -1, -1, $WS_POPUP, BitOR($WS_EX_LAYERED, $WS_EX_TRANSPARENT, $WS_EX_MDICHILD), $h_InjectionGUI)
	GUISetBkColor(0x989898, $h_LabelGUI)
	$h_Label = GUICtrlCreateLabel("Injecting...", 0, 0, 200, 100, BitOR($SS_CENTER, $SS_CENTERIMAGE))
	GUICtrlSetFont($h_Label, 20, $FW_BOLD)
	GUICtrlSetBkColor($h_Label, $GUI_BKCOLOR_TRANSPARENT)
	_WinAPI_SetLayeredWindowAttributes($h_LabelGUI, 0x989898)

	GUISetState(@SW_SHOW, $h_InjectionGUI)
	GUISetState(@SW_SHOW, $h_LabelGUI)

	Sleep($g_InjectionDelay)

	Return True
EndFunc   ;==>PreInject