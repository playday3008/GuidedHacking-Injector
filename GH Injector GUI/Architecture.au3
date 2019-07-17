;FUNCTION LIST IN FILE ORDER:

;===================================================================================================
; Function........:  GetDosHeader($hFile)
;
; Description.....:  Reads the dos header of a pe file into memory and returns a pointer.
;
; Parameter(s)....:  $hFile - A file handle or absolute path to the file.
;
; Return Value(s).:  On Success - Returns the pointer to the allocated dll struct.
;                    On Failure - Returns 0.
;===================================================================================================
; Function........:  GetNTHeader($hFile, $Offset)
;
; Description.....:  Reads the nt header of a pe file into memory and returns a pointer.
;
; Parameter(s)....:  $hFile 	- A file handle or absolute path to the file.
;					 $Offset 	- The offset from the beginning of the file to nt header.
;									This offset is defined by the e_magic member of the dos header.
;
; Return Value(s).:  On Success - Returns the pointer to the allocated dll struct.
;                    On Failure - Returns 0.
;===================================================================================================
; Function........:  GetFileArchitecture($Path)
;
; Description.....:  Determines the architecture of a PE file by checking the Machine member
;						of the nt header of the file.
;
; Parameter(s)....:  $Path 		- A file handle or absolute path to the file.
;
; Return Value(s).:  On Success - "x64" if the file is IMAGE_FILE_MACHINE_AMD64 and
;									"x86" if the file is IMAGE_FILE_MACHINE_I386.
;                    On Failure - Returns 0.
;									@error = 1: invalid MZ signature (dosheader.e_magic)
;									@error = 2: invalid PE signature (ntheader.Signature)
;									@error = 3: Machine is not x86 nor x64
;===================================================================================================
; Function........:  Is64BitProcess($hTargetProcess)
;
; Description.....:  Determines whether a process is a 64bit process or not.
;
; Parameter(s)....:  $hTargetProcess	- A handle to the target process. This handle must have
;											the PROCESS_QUERY_LIMITED_INFORMATION access right.
;
; Return Value(s).:  On Success - Returns true (process is x64) or false (process is not x64).
;                    On Failure - Returns 0.
;===================================================================================================

#include <WinAPI.au3>
#include <WinAPIEx.au3>

#Region Global Definitions

Global Const $IMAGE_DOS_HEADER = _
	"struct;				" & _
		"WORD	e_magic;	" & _
		"WORD   e_cblp;     " & _
		"WORD   e_cp;       " & _
		"WORD   e_crlc;     " & _
		"WORD   e_cparhdr;  " & _
		"WORD   e_minalloc; " & _
		"WORD   e_maxalloc; " & _
		"WORD   e_ss;       " & _
		"WORD   e_sp;       " & _
		"WORD   e_csum;     " & _
		"WORD   e_ip;       " & _
		"WORD   e_cs;       " & _
		"WORD   e_lfarlc;   " & _
		"WORD   e_ovno;     " & _
		"WORD   e_res[4];   " & _
		"WORD   e_oemid;    " & _
		"WORD   e_oeminfo;  " & _
		"WORD   e_res2[10]; " & _
		"LONG   e_lfanew;   " & _
	"endstruct				"

Global Const $IMAGE_NT_HEADERS_STRIPPED = _
	"struct;							" & _
		"DWORD 	Signature;				" & _
		"WORD 	Machine;				" & _
		"WORD 	NumberOfSections;		" & _
		"DWORD 	TimeDateStamp;			" & _
		"DWORD	PointerToSymbolTable;	" & _
		"DWORD	NumberOfSymbols;		" & _
		"WORD	SizeOfOptionalHeader;	" & _
		"WORD	Characteristics;		" & _
	"endstruct							"

#EndRegion

Func GetDosHeader($hFile)

    _WinAPI_SetFilePointer($hFile, 0)
    $dos_header 	= DllStructCreate($IMAGE_DOS_HEADER)
    $pdos_header 	= DllStructGetPtr($dos_header)
	$SizeOut 		= 0
    _WinAPI_ReadFile($hFile, $pdos_header, DllStructGetSize($dos_header), $SizeOut)

	Return $dos_header

EndFunc   ;==>GetDosHeader

Func GetNTHeader($hFile, $Offset)

	_WinAPI_SetFilePointer($hFile, $Offset)
	$nt_header	= DllStructCreate($IMAGE_NT_HEADERS_STRIPPED)
	$pnt_header	= DllStructGetPtr($nt_header)
	$SizeOut 	= 0
	_WinAPI_ReadFile($hFile, $pnt_header, DllStructGetSize($nt_header), $SizeOut)

	Return $nt_header

EndFunc   ;==>GetNTHeader

Func GetFileArchitecture($Path)

    $hFile = _WinAPI_CreateFile($Path, 2, 2)

	$dos_header = GetDosHeader($hFile)
	If ($dos_header.e_magic <> 0x5A4D) Then
		_WinAPI_CloseHandle($hFile)
		SetError(1)
		Return $dos_header.e_magic
	EndIf

	$nt_header = GetNTHeader($hFile, $dos_header.e_lfanew)
	If ($nt_header.Signature <> 0x4550) Then
		_WinAPI_CloseHandle($hFile)
		SetError(2)
		Return $nt_header.Signature
	EndIf

	_WinAPI_CloseHandle($hFile)

	$Architecture = ""
	If ($nt_header.Machine = $IMAGE_FILE_MACHINE_I386) Then
		$Architecture = "x86"
	ElseIf ($nt_header.Machine = $IMAGE_FILE_MACHINE_AMD64) Then
		$Architecture = "x64"
	Else
		SetError(3)
		Return $nt_header.Machine
	EndIf

	Return $Architecture

EndFunc   ;==>GetNTHeader

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