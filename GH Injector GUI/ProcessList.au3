#include "Include.au3"
#include "Misc.au3"

Global Const $TH32CS_SNAPPROCESS 		= 0x00000002
Global Const $ProcessSessionInformation = 24

Global Const $PROCESSENTRY32 = _
	"struct;								" & _
		"DWORD 		dwSize;					" & _
		"DWORD 		cntUsage;				" & _
		"DWORD 		th32ProcessID;			" & _
		"UINT_PTR 	th32DefaultHeapID;		" & _
		"DWORD 		th32ModuleID;			" & _
		"DWORD 		cntThreads;				" & _
		"DWORD 		th32ParentProcessID;	" & _
		"LONG 		pcPriClassBase;			" & _
		"DWORD 		dwFlags;				" & _
		"CHAR 		szExeFile[260];			" & _
	"endstruct								"

Global Const $PROCESS_SESSION_INFORMATION = _
	"struct;			" & _
		"UINT SessionId	" & _
	"endstruct			"

Global $l_SortSense = [False, False, False]

$g_ProcNameFilter 			= ""
$l_h_L_ProcList 			= 0
$l_L_DoubleClickedIndex 	= -1
$l_ProcListX 				= -1
$l_ProcListY 				= -1
Local $hImageList			= 0

Func GetSessionId($hTargetProcess)

	$psi 		= DllStructCreate($PROCESS_SESSION_INFORMATION)
	$ppsi 		= DllStructGetPtr($psi)
	$psi_size 	= DllStructGetSize($psi)

	$ntRet = DllCall("ntdll.dll", _
		"LONG", "NtQueryInformationProcess", _
			"HANDLE", 	$hTargetProcess, _
			"DWORD", 	$ProcessSessionInformation, _
			"STRUCT*", 	$ppsi, _
			"ULONG", 	$psi_size, _
			"ULONG*", 	0 _
	)

	If (NOT IsArray($ntRet) OR ($ntRet[0] < 0)) Then
		Return -1
	EndIf
	Return $psi.SessionId

EndFunc   ;==>GetSessionId

Func Is64BitProcess($hTargetProcess)

	$bIs64BitWin = False

	$bOut = False
	Local $bRet = DllCall("kernel32.dll", _
		"BOOL", "IsWow64Process", _
			"HANDLE", 	-1, _
			"BOOL*", 	$bOut _
	)

	If (NOT IsArray($bRet) OR ($bRet[0] = 0)) Then
		Return 0
	EndIf

	$bOut = $bRet[2]
	If ($bOut <> 0) Then
		$bIs64BitWin = True
	EndIf

	Local $bRet = DllCall("kernel32.dll", _
		"BOOL", "IsWow64Process", _
			"HANDLE", 	$hTargetProcess, _
			"BOOL*", 	$bOut _
	)

	If (NOT IsArray($bRet) OR ($bRet[0] = 0)) Then
		Return 0
	EndIf

	$bOut = $bRet[2]
	If ($bIs64BitWin AND NOT $bOut) Then
		Return True
	EndIf

	Return False

EndFunc   ;==>Is64BitProcess

Func GetProcessExePath($hProc)

	$ret = DllCall("kernel32.dll", _
		"BOOL", "QueryFullProcessImageNameA", _
			"HANDLE", 	$hProc[0], _
			"DWORD", 	0, _
			"STR", 		"", _
			"DWORD*", 	260 _
	)

	If (NOT @error AND _WinAPI_IsWow64Process() AND IsArray($ret) AND $ret[0] AND NOT FileExists($ret[3])) Then
		$string_split = _StringExplode($ret[3], "\System32\")
		If (IsArray($string_split) AND UBound($string_split) = 2) Then
			$ret[3] = $string_split[0] & "\Sysnative\" & $string_split[1]
		EndIf
	EndIf

	Return $ret

EndFunc   ;==>GetProcessExePath

Func ListProcesses($h_L_Processes, $Mode, $CurrentSessionOnly, $Filter)

	_GUICtrlListView_DeleteAllItems($h_L_Processes)

	Local $hK32 = DllOpen("kernel32.dll")
	If (@error OR ($hK32 = -1)) Then
		MsgBox($MB_ICONERROR, "Error", "Can't create process list.")
		Return
	EndIf

	Local $hSnap = DllCall($hK32, _
		"HANDLE", "CreateToolhelp32Snapshot", _
			"DWORD", $TH32CS_SNAPPROCESS, _
			"DWORD", 0 _
	)

	If (NOT IsArray($hSnap) OR ($hSnap[0] = 0)) Then
		MsgBox($MB_ICONERROR, "Error", "Can't create process list.")
		DllClose($hK32)
		Return
	EndIf

	Local $ProcessData[256][4]
	$Count = 0

	$OwnSession = GetSessionId(-1)

	$PE32 	= DllStructCreate($PROCESSENTRY32)
	$pPE32 	= DllStructGetPtr($PE32)

	$PE32.dwSize = DllStructGetSize($PE32)
	Local $bRet = DllCall($hK32, _
		"BOOL", "Process32First", _
			"HANDLE", 	$hSnap[0], _
			"STRUCT*", 	$pPE32 _
	)

	While (IsArray($bRet) AND $bRet[0] <> 0)
		$ProcessData[$Count][0] = $PE32.th32ProcessID
		$ProcessData[$Count][1] = $PE32.szExeFile
		$ProcessData[$Count][2] = "---"

		$bRet = DllCall($hK32, _
			"BOOL", "Process32Next", _
				"HANDLE",	$hSnap[0], _
				"STRUCT*", 	$pPE32 _
		)

		If (StringCompare($Filter, "")) Then
			If (StringInStr($ProcessData[$Count][1], $Filter, $STR_NOCASESENSE, 1, 1, StringLen($ProcessData[$Count][1]) - 4) = 0) Then
				ContinueLoop
			EndIf
		EndIf

		If ($ProcessData[$Count][0] == @AutoItPID) Then
			ContinueLoop
		EndIf

		$hProc_info = DllCall($hK32, _
			"HANDLE", "OpenProcess", _
				"DWORD", 	$PROCESS_QUERY_LIMITED_INFORMATION, _
				"INT", 		0, _
				"DWORD", 	$ProcessData[$Count][0] _
		)

		If (NOT IsArray($hProc_info) OR ($hProc_info[0] = 0)) Then
			$ProcessData[$Count][3] = 0
			If ($CurrentSessionOnly = 0) Then
				$Count += 1
			EndIf
			ContinueLoop
		EndIf

		If (Is64BitProcess($hProc_info[0])) Then
			$ProcessData[$Count][2] = "x64"
		Else
			$ProcessData[$Count][2] = "x86"
		EndIf

		If ($CurrentSessionOnly = 1) Then
			If (GetSessionId($hProc_info[0]) <> $OwnSession) Then
				DllCall($hK32, _
					"BOOL", "CloseHandle", _
						"HANDLE", $hProc_info[0] _
				)
				ContinueLoop
			EndIf
		EndIf

		$dllRet = GetProcessExePath($hProc_info)

		DllCall($hK32, _
			"BOOL", "CloseHandle", _
				"HANDLE", $hProc_info[0] _
		)

		If (IsArray($dllRet) AND ($dllRet[0] <> 0)) Then
			$ProcessData[$Count][3] = $dllRet[3]
		Else
			$ProcessData[$Count][3] = 0
		EndIf

		$Count += 1
	WEnd

	DllCall($hK32, _
		"BOOL", "CloseHandle", _
			"HANDLE", $hSnap[0] _
	)

	DllClose($hK32)

	If ($Count > 1) Then
		$CurrentSortSense = $l_SortSense[$Mode]
		_ArraySort($ProcessData, $l_SortSense[$Mode], 0, $Count - 1, $Mode)

		$l_SortSense[0] = False
		$l_SortSense[1] = False
		$l_SortSense[2] = False

		If ($CurrentSortSense = False) Then
			$l_SortSense[$Mode] = True
		EndIf
	EndIf

	$hImageList = _GUIImageList_Create(16, 16, 5, 1)
	For $i = 0 To $Count - 1 Step 1
		If (NOT IsString($ProcessData[$i][3])) Then
			_GUIImageList_AddIcon($hImageList, @SystemDir & "\imageres.dll", 11)
		Else
			If (_GUIImageList_AddIcon($hImageList, $ProcessData[$i][3], 0) = -1) Then
				_GUIImageList_AddIcon($hImageList, @SystemDir & "\imageres.dll", 11)
			EndIf
		EndIf
	Next
	_GUICtrlListView_SetImageList($h_L_Processes, $hImageList, 1)

	For $i = 0 To $Count - 1 Step 1
		_GUICtrlListView_AddItem($h_L_Processes, "", $i)
		_GUICtrlListView_AddSubItem($h_L_Processes, $i, $ProcessData[$i][0], 1)
		_GUICtrlListView_AddSubItem($h_L_Processes, $i, $ProcessData[$i][1], 2)
		_GUICtrlListView_AddSubItem($h_L_Processes, $i, $ProcessData[$i][2], 3)
	Next

	Return $Count

EndFunc   ;==>ListProcesses

Func WM_NOTIFY_ProcessPicker($hwnd, $uMsg, $wParam, $lParam)

	$tNMHDR = DllStructCreate($tagNMHDR, $lParam)

	$hListView = $l_h_L_ProcList
	If (NOT IsHWnd($hListView)) Then
		$hListView = GUICtrlGetHandle($l_h_L_ProcList)
	EndIf

	If (HWnd($tNMHDR.hwndFrom) = $hListView) Then
		If ($tNMHDR.code = $NM_DBLCLK) Then
			$tInfo = DllStructCreate($tagNMITEMACTIVATE, $lParam)
			$l_L_DoubleClickedIndex = $tInfo.Index

			Return 0
		EndIf
	EndIf

	Return $GUI_RUNDEFMSG

EndFunc   ;==>WM_NOTIFY_ProcessPicker

Func CreateProcessList()

	$Width 		= 270
	$lHeight 	= 385

	$h_Select = GUICreate("Select a process (0)", $Width, $lHeight, $l_ProcListX, $l_ProcListY, BitXOR($GUI_SS_DEFAULT_GUI, $WS_MINIMIZEBOX), $WS_EX_TOPMOST)
	$h_L_List = GUICtrlCreateListView("|PID|Name|Type", 0, 0, $Width, $lHeight - 80, -1, BitOR($LVS_EX_GRIDLINES, $LVS_EX_FULLROWSELECT, $LVS_EX_SUBITEMIMAGES))
	$l_h_L_ProcList = $h_L_List

	_GUICtrlListView_SetColumnWidth($h_L_List, 0, $Width / 12)
	_GUICtrlListView_SetColumnWidth($h_L_List, 1, $Width / 6)
	_GUICtrlListView_SetColumnWidth($h_L_List, 2, $Width / 25 * 13)
	_GUICtrlListView_SetColumnWidth($h_L_List, 3, $Width / 7)

	$h_L_ProcFilterLabel 	= GUICtrlCreateLabel("Filter process list:", 6, $lHeight - 74, 80, 15)
	$h_I_ProcFilter 		= GUICtrlCreateInput($g_ProcNameFilter, 90, $lHeight - 76, $Width - 96, 17)
	$h_B_Select 			= GUICtrlCreateButton("Select", 5, $lHeight - 55, $Width - 10, 30)
	$h_C_CurrSession 		= GUICtrlCreateCheckbox("Current session processes only", $Width - 170, $lHeight - 24)
		GUICtrlSetState($h_C_CurrSession, $GUI_CHECKED)
	$h_B_Refresh 			= GUICtrlCreateButton("Refresh", 5, $lHeight - 22, $Width - 180, 17)

	$ProcessCount 			= ListProcesses($h_L_List, 1, 1, $g_ProcNameFilter)
	WinSetTitle($h_Select, "", "Select a process (" & $ProcessCount & ")")

	GUISetState(@SW_SHOW)

	$lPID 				= -1
	$lProcArch 			= ""
	$UpdateListFromMask = False
	$TempPrcoNameFilter = $g_ProcNameFilter

	$h_User32 = DllOpen("user32.dll")

	_WinAPI_SetFocus(GUICtrlGetHandle($h_I_ProcFilter))
	ControlSend($h_Select, "", $h_I_ProcFilter, "{END}")

	While (True)
		Sleep(5)

		$TempPrcoNameFilter = GUICtrlRead($h_I_ProcFilter)
		If (StringCompare($TempPrcoNameFilter, $g_ProcNameFilter)) Then
			$UpdateListFromMask = True
		EndIf

		$Msg = GUIGetMsg($h_Select)
		Select
			Case $Msg = $GUI_EVENT_CLOSE
				$lPID = -1
				ExitLoop

			Case $l_L_DoubleClickedIndex <> -1
				$lPID 		= _GUICtrlListView_GetItemText($h_L_List, $l_L_DoubleClickedIndex, 1)
				$lProcArch 	= _GUICtrlListView_GetItemText($h_L_List, $l_L_DoubleClickedIndex, 3)
				If ($lProcArch = "---") Then
					MsgBox(BitOR($MB_ICONERROR, $MB_TOPMOST), "Error", "Can't attach to process.")
					$l_L_DoubleClickedIndex = -1
					ContinueLoop
				EndIf

				$l_L_DoubleClickedIndex = -1
				ExitLoop

			Case $Msg = $h_B_Select
				Local $Index = _GUICtrlListView_GetSelectedIndices($h_L_List, True)
				If ($Index[0] = 0) Then
					MsgBox(BitOR($MB_ICONERROR, $MB_TOPMOST), "Error", "Please select a process first.")
					ContinueLoop
				EndIf

				$lPID 		= _GUICtrlListView_GetItemText($h_L_List, $Index[1], 1)
				$lProcArch 	= _GUICtrlListView_GetItemText($h_L_List, $Index[1], 3)
				If ($lProcArch = "---") Then
					MsgBox(BitOR($MB_ICONERROR, $MB_TOPMOST), "Error", "Can't attach to the specified process.")
					Sleep(100)
					ContinueLoop
				EndIf

				ExitLoop

			Case $Msg = $h_L_List
				$ClickedCol = GUICtrlGetState($h_L_List)
				If ($ClickedCol <> 0) Then
					$bSession = (BitAND(GUICtrlRead($h_C_CurrSession), $GUI_CHECKED) <> 0)
					$ProcessCount = ListProcesses($h_L_List, $ClickedCol - 1, $bSession, $g_ProcNameFilter)
					WinSetTitle($h_Select, "", "Select a process (" & $ProcessCount & ")")
				EndIf

			Case $Msg = $h_C_CurrSession
				$bSession = (BitAND(GUICtrlRead($h_C_CurrSession), $GUI_CHECKED) <> 0)
				$l_SortSense[1] = False
				$ProcessCount = ListProcesses($h_L_List, 1, $bSession, $g_ProcNameFilter)
				WinSetTitle($h_Select, "", "Select a process (" & $ProcessCount & ")")

			Case $Msg = $h_B_Refresh
				$bSession = (BitAND(GUICtrlRead($h_C_CurrSession), $GUI_CHECKED) <> 0)
				$l_SortSense[1] = False
				$ProcessCount = ListProcesses($h_L_List, 1, $bSession, $g_ProcNameFilter)
				WinSetTitle($h_Select, "", "Select a process (" & $ProcessCount & ")")

			Case $UpdateListFromMask = True
				$UpdateListFromMask = False
				$g_ProcNameFilter = GUICtrlRead($h_I_ProcFilter)
				$bSession = (BitAND(GUICtrlRead($h_C_CurrSession), $GUI_CHECKED) <> 0)
				$l_SortSense[1] = False
				$ProcessCount = ListProcesses($h_L_List, 1, $bSession, $g_ProcNameFilter)
				WinSetTitle($h_Select, "", "Select a process (" & $ProcessCount & ")")

			Case _IsPressed("0D", $h_User32)
				Local $Index = _GUICtrlListView_GetSelectedIndices($h_L_List, True)
				If ($Index[0] = 0) Then
					ContinueLoop
				EndIf

				$lPID 		= _GUICtrlListView_GetItemText($h_L_List, $Index[1], 1)
				$lProcArch 	= _GUICtrlListView_GetItemText($h_L_List, $Index[1], 3)
				If ($lProcArch = "---") Then
					MsgBox(BitOR($MB_ICONERROR, $MB_TOPMOST), "Error", "Can't attach to process.")
					ContinueLoop
				EndIf

				ExitLoop

		EndSelect
	WEnd

	DllClose($h_User32)

	Local $Pos = WinGetPos($h_Select)
	If (IsArray($Pos)) Then
		$ProcListX = $Pos[0]
		$ProcListY = $Pos[1]
	EndIf

	_GUIImageList_Destroy($hImageList)

	GUISetState(@SW_HIDE)
	GUIDelete($h_Select)

	$l_SortSense[1] = False

	Return $lPID

EndFunc   ;==>CreateProcessList