#include "Include.au3"

Func SaveSettings()

	IniWrite($g_ConfigPath, "CONFIG", "PROCESS", 		      ($g_Processname			))
	IniWrite($g_ConfigPath, "CONFIG", "PID", 			Number($g_PID					))
	IniWrite($g_ConfigPath, "CONFIG", "PROCESSBYNAME", 	Number($g_ProcessByName			))
	IniWrite($g_ConfigPath, "CONFIG", "DELAY", 			Number($g_InjectionDelay		))
	IniWrite($g_ConfigPath, "CONFIG", "LASTDIR", 		      ($g_LastDirectory			))
	IniWrite($g_ConfigPath, "CONFIG", "AUTOINJ", 		Number($g_AutoInjection			))
	IniWrite($g_ConfigPath, "CONFIG", "CLOSEONINJ",		Number($g_CloseAfterInjection	))
	IniWrite($g_ConfigPath, "CONFIG", "METHOD", 		Number($g_InjectionMethod		))
	IniWrite($g_ConfigPath, "CONFIG", "LAUNCHMETHOD",	Number($g_LaunchMethod			))
	IniWrite($g_ConfigPath, "CONFIG", "FLAGS", 			Number($g_InjectionFlags		))
	IniWrite($g_ConfigPath, "CONFIG", "IGNOREUPDATES", 	Number($g_IgnoreUpdates			))
	IniWrite($g_ConfigPath, "CONFIG", "PROCNAMEFILTER", 	  ($g_ProcNameFilter		))

EndFunc   ;==>SaveSettings

Func SaveFiles($h_DllList)

	IniWriteSection($g_ConfigPath, "FILES", "")

	$Count = _GUICtrlListView_GetItemCount($h_DllList)
	For $i = 0 To $Count - 1 Step 1
		$Path = _GUICtrlListView_GetItemText($h_DllList, $i, 2)

		If (_GUICtrlListView_GetItemChecked($h_DllList, $i)) Then
			$Path &= "1"
		Else
			$Path &= "0"
		EndIf

		IniWrite($g_ConfigPath, "FILES", $i, $Path)
	Next

EndFunc   ;==>SaveFiles

Func ResetSettings()

	FileDelete($g_ConfigPath)

	$g_Processname 			= "Broihon.exe"
	$g_PID					= 0
	$g_ProcessByName		= True
	$g_InjectionDelay		= 0
	$g_LastDirectory		= @DesktopDir & "\"
	$g_AutoInjection 		= False
	$g_CloseAfterInjection 	= False
	$g_InjectionMethod		= 0
	$g_LaunchMethod			= False
	$g_InjectionFlags		= 0
	$g_IgnoreUpdates		= False
	$g_ProcNameFilter		= ""

	SaveSettings()

	IniWriteSection($g_ConfigPath, "FILES", "")

EndFunc   ;==>ResetSettings

Func LoadSettings()

	If (NOT FileExists($g_ConfigPath)) Then
		ResetSettings()
		Return
	EndIf

	$g_Processname 			= 		(IniRead($g_ConfigPath, "CONFIG", "PROCESS", 		      ($g_Processname			)))
	$g_PID 					= Number(IniRead($g_ConfigPath, "CONFIG", "PID", 			Number($g_PID					)))
	$g_ProcessByName	 	= Number(IniRead($g_ConfigPath, "CONFIG", "PROCESSBYNAME", 	Number($g_ProcessByName			)))
	$g_InjectionDelay		= Number(IniRead($g_ConfigPath, "CONFIG", "DELAY", 			Number($g_InjectionDelay		)))
	$g_LastDirectory 		= 		(IniRead($g_ConfigPath, "CONFIG", "LASTDIR", 			  ($g_LastDirectory			)))
	$g_AutoInjection 		= Number(IniRead($g_ConfigPath, "CONFIG", "AUTOINJ", 		Number($g_AutoInjection			)))
	$g_CloseAfterInjection 	= Number(IniRead($g_ConfigPath, "CONFIG", "CLOSEONINJ", 	Number($g_CloseAfterInjection	)))
	$g_InjectionMethod 		= Number(IniRead($g_ConfigPath, "CONFIG", "METHOD", 		Number($g_InjectionMethod		)))
	$g_LaunchMethod		 	= Number(IniRead($g_ConfigPath, "CONFIG", "LAUNCHMETHOD",	Number($g_LaunchMethod			)))
	$g_InjectionFlags 		= Number(IniRead($g_ConfigPath, "CONFIG", "FLAGS", 			Number($g_InjectionFlags		)))
	$g_IgnoreUpdates 		= Number(IniRead($g_ConfigPath, "CONFIG", "IGNOREUPDATES", 	Number($g_IgnoreUpdates			)))
	$g_ProcNameFilter 		= 		(IniRead($g_ConfigPath, "CONFIG", "PROCNAMEFILTER", 	  ($g_ProcNameFilter		)))

EndFunc   ;==>LoadSettings

Func LoadFiles($h_DllList)

	Local $Files = IniReadSection($g_ConfigPath, "FILES")
	If (@error) Then
		Return
	EndIf

	For $i = 0 To $Files[0][0] - 1 Step 1

		$Path 		= StringTrimRight($Files[$i + 1][1], 1)
		$FileTicked = StringTrimLeft($Files[$i + 1][1], StringLen($Files[$i + 1][1]) - 1)

		If (FileExists($Path)) Then
			Local $Split = StringSplit($Path, "\")
			_GUICtrlListView_AddItem($h_DllList, "", $i)
			_GUICtrlListView_AddSubItem($h_DllList, $i, $Split[$Split[0]], 1)
			_GUICtrlListView_AddSubItem($h_DllList, $i, $Path, 2)
			_GUICtrlListView_AddSubItem($h_DllList, $i, 0, 3)

			If ($FileTicked = "1") Then
				_GUICtrlListView_SetItemChecked($h_DllList, $i)
			EndIf
		Else
			IniDelete($g_ConfigPath, "FILES", $Files[$i + 1][0])
		EndIf
	Next

EndFunc   ;==>LoadFiles