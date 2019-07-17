#include "Include.au3"

Func Update()

	$VersionRef 		= "http://pastebin.com/raw/npsqXhuQ"
	$DownloadRef 		= "http://pastebin.com/raw/XwHpPeJC"

	$g_NewestVersion 	= _INetGetSource($VersionRef)

	If ($g_NewestVersion) Then
		If (StringCompare($g_CurrentVersion, $g_NewestVersion)) Then
			$h_GUI_Update = GUICreate("New version available", 250, 90, -1, -1, BitXOR($GUI_SS_DEFAULT_GUI, $WS_MINIMIZEBOX), $WS_EX_TOPMOST)
			$h_L_InfoText = GUICtrlCreateLabel("This version of the GH Injector is outdated." & @CRLF & "The newest version is V" & $g_NewestVersion & ".", 20, 10)
			$h_B_Update = GUICtrlCreateButton("Update", 20, 43, 87)
			$h_B_Cancel = GUICtrlCreateButton("Skip", 137, 43, 87)
			$h_C_Ignore = GUICtrlCreateCheckbox("Ignore future updates", 20, 70)

			GUISetState(@SW_SHOW)

			While (True)
				$Msg = GUIGetMsg()
				Select
					Case $Msg = $GUI_EVENT_CLOSE
						ExitLoop

					Case $Msg = $h_B_Cancel
						ExitLoop

					Case $Msg = $h_C_Ignore
						If (GUICtrlRead($h_C_Ignore) = $GUI_CHECKED) Then
							GUICtrlSetState($h_B_Update, $GUI_DISABLE)
							$g_IgnoreUpdates = True
						Else
							GUICtrlSetState($h_B_Update, $GUI_ENABLE)
							$g_IgnoreUpdates = False
						EndIf

					Case $Msg = $h_B_Update
						$DownloadLink = _INetGetSource($DownloadRef)
						GUIDelete($h_GUI_Update)

						$Path = FileSelectFolder("Select path", @ScriptDir)
						If ($Path) Then
							InetGet($DownloadLink, $Path & "\GH Injector V" & $g_NewestVersion & ".zip")
							MsgBox($MB_ICONINFORMATION, "Updated", "New version has been downloaded successfully.")
							ShellExecute($Path)
							Exit
						EndIf
						ExitLoop
				EndSelect
			WEnd

			GUISetState(@SW_HIDE)
			GUIDelete($h_GUI_Update)
		EndIf
	EndIf

EndFunc   ;==>Update