#include-once

#include <ColorConstants.au3>
#include <EditConstants.au3>
#include <File.au3>
#include <FontConstants.au3>
#include <GuiComboBox.au3>
#include <GUIConstantsEx.au3>
#include <GUIImageList.au3>
#include <GUIListView.au3>
#include <GuiMenu.au3>
#include <Inet.au3>
#include <Process.au3>
#include <StaticConstants.au3>
#include <String.au3>
#include <WinAPI.au3>
#include <WinAPIEx.au3>
#include <WindowsConstants.au3>

Global Const 	$g_CurrentVersion 	= "2.4"
Global 			$g_NewestVersion 	= "2.4"
Global Const 	$g_ConfigPath 		= @ScriptDir & "\GH Injector Config.ini"

Global $g_Processname 			= "Broihon.exe"
Global $g_PID					= 0
Global $g_ProcessByName			= True
Global $g_InjectionDelay		= 0
Global $g_LastDirectory			= @DesktopDir & "\"
Global $g_AutoInjection 		= False
Global $g_CloseAfterInjection 	= False
Global $g_LaunchMethod			= 0
Global $g_InjectionMethod		= 0
Global $g_InjectionFlags		= 0
Global $g_IgnoreUpdates			= False
Global $g_ProcNameFilter		= ""

Global Const $INJ_ERASE_HEADER				= 0x01
Global Const $INJ_FAKE_HEADER				= 0x02
Global Const $INJ_UNLINK_FROM_PEB			= 0x04
Global Const $INJ_SHIFT_MODULE				= 0x08
Global Const $INJ_CLEAN_DATA_DIR			= 0x10
Global Const $INJ_HIDE_THREAD_FROM_DEBUGGER	= 0x20