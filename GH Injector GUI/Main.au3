#NoTrayIcon
#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=GH Icon.ico
#AutoIt3Wrapper_Outfile=GH Injector.exe
#AutoIt3Wrapper_UseUpx=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

#include "Update.au3"
#include "Injection.au3"

Func Main()

	If (NOT FileExists(@ScriptDir & "\GH Injector - x64.exe")) Then
		MsgBox($MB_ICONERROR, "Error", '"GH Injector - x64.exe" is missing')
		Exit
	EndIf

	If (NOT FileExists(@ScriptDir & "\GH Injector - x86.exe")) Then
		MsgBox($MB_ICONERROR, "Error", '"GH Injector - x86.exe" is missing')
		Exit
	EndIf

	LoadSettings()

	If NOT($g_IgnoreUpdates) Then
		Update()
	EndIf

	CreateGUI()

	LoadFiles($h_L_Dlls)

	$GUI_MSG = $GUI_RETURN
	While ($GUI_MSG <> $GUI_EXIT)
		$GUI_MSG = UpdateGUI()

		If ($GUI_MSG = $GUI_RESET) Then
			ResetSettings()
			ResetGUI()
			$GUI_MSG = UpdateGUI()

		ElseIf ($GUI_MSG = $GUI_INJECT OR $g_AutoInjection) Then
			$injection_state = PreInject()
			If ($injection_state = True) Then
				Inject()
			EndIf

		ElseIf ($GUI_MSG = $GUI_UPDATE) Then
			Update()
		EndIf

		Sleep(10)
	WEnd

	SaveFiles($h_L_Dlls)

	SaveSettings()

	CloseGUI()

EndFunc   ;==>Main

Main()