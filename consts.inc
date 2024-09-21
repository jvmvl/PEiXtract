INCLUDE		WINDOWS.INC
INCLUDE		USER32.INC
INCLUDE		KERNEL32.INC
INCLUDE		SHELL32.INC
INCLUDE		ADVAPI32.INC
INCLUDE		GDI32.INC
INCLUDE		COMCTL32.INC
INCLUDE		COMDLG32.INC
INCLUDE		MASM32.INC
INCLUDE		MACROS.ASM
INCLUDELIB	USER32.LIB
INCLUDELIB	KERNEL32.LIB
INCLUDELIB	SHELL32.LIB
INCLUDELIB	ADVAPI32.LIB
INCLUDELIB	GDI32.LIB
INCLUDELIB	COMCTL32.LIB
INCLUDELIB	COMDLG32.LIB
INCLUDELIB	MASM32.LIB
INCLUDELIB 	WINMM.LIB
include 	cryptohash.inc
includelib 	cryptohash.lib


DlgProc				PROTO :DWORD,:DWORD,:DWORD,:DWORD
FileHeader			PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetNULL				PROTO :DWORD,:DWORD
SetInfos			PROTO :DWORD
OpenPEFile			PROTO :DWORD,:DWORD
IsValidPE			PROTO :DWORD,:DWORD
List				PROTO :DWORD,:DWORD
MachineTypeDlg		PROTO :DWORD,:DWORD,:DWORD,:DWORD
TimeDateStampCDlg	PROTO :DWORD,:DWORD,:DWORD,:DWORD
CharacteristicsDlg	PROTO :DWORD,:DWORD,:DWORD,:DWORD
OptionalHeaderDlg	PROTO :DWORD,:DWORD,:DWORD,:DWORD
DosHeaderDlg		PROTO :DWORD,:DWORD,:DWORD,:DWORD
SectionHeaderDlg	PROTO :DWORD,:DWORD,:DWORD,:DWORD
DataDirectoriesDlg	PROTO :DWORD,:DWORD,:DWORD,:DWORD
SubsystemDlg		PROTO :DWORD,:DWORD,:DWORD,:DWORD
ProcessManagerDlg	PROTO :DWORD,:DWORD,:DWORD,:DWORD

InsertColumns    	PROTO
AddItem         	PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD


.CONST

; DIALOG IDS
IDD_MAIN					equ 	1001
IDD_FiLEHEADER 				equ 	2018
IDD_MACHINETYPE				equ		2036
IDD_CHARACTERISTICS			equ		2054
IDD_OPTHEADER				equ		2071
IDD_TDSTAMP					equ		2037
IDD_DOSHEADER				equ		2138
IDD_DIRECTORIES				equ		2176
IDD_SUBSYSTEM				equ		2248
IDD_SECHEADER				equ		2252
IDD_PROCMANAGER				equ		2256


IDC_FiLENAME				equ 	1003
IDC_BROWSE					equ		1004
IDC_FiLESIZE				equ 	1005
IDC_FiLEHASH				equ 	1006

IDC_ENTRYPOINT 				equ 	1007
IDC_IMAGEBASE 				equ 	1008
IDC_SIZEOFIMAGE 			equ 	1009
IDC_BASEOFCODE 				equ 	1010
IDC_BASEOFDATA 				equ 	1011
IDC_SECTIONALIGNMENT 		equ 	1012
IDC_FILEALIGNMENT 			equ 	1013
IDC_MAGIC 					equ 	1014
IDC_SUBSYSTEM 				equ 	1015
IDC_NUMBEROFSECTIONS 		equ 	1016
IDC_TIMEDATESTAMP 			equ 	1017
IDC_SIZEOFHEADERS 			equ 	1018
IDC_CHARACTERISTICS 		equ 	1019
IDC_CHECKSUM 				equ 	1020
IDC_SIZEOFOPTIONALHEADER 	equ 	1021
IDC_NUMBEROFRVAANDSIZES 	equ 	1022

;MENU
IDM_OPENFILE				equ		102
IDM_DOSHEADER				equ		128
IDM_FiLEHEADER 				equ 	104
IDM_OPTiONALHEADER 			equ 	105
IDM_SECTiONS 				equ 	106
IDM_DiRECTORiES 			equ 	107
IDM_HEXViEW 				equ 	108
IDM_PROCMGR 				equ 	110
IDM_TDSADJUST 				equ 	111
IDM_CAVEFiND 				equ 	112
IDM_FHASH 					equ 	113
IDM_COMPARE 				equ 	114
IDM_STRViEW 				equ 	115
IDM_ADDEXP 					equ 	117
IDM_ONTOP 					equ 	118
IDM_TRANS 					equ 	119
IDM_EULA 					equ 	121
IDM_ABOUT 					equ 	122

IDC_MACHiNE 				equ		2027
IDC_NUMOFSEC 				equ 	2028
IDC_TDSTAMP 				equ 	2029
IDC_POiNTER2SYMTAB 			equ 	2030
IDC_NUMOFSYM 				equ 	2031
IDC_SiZEOFOPTiONALH 		equ 	2032
IDC_CHARACT 				equ 	2033

BaseTimeLow 				equ 	0D53E8000h
BaseTimeHigh 				equ 	19DB1DEh

IDM_MACHINETYPE_BTN			equ		2042
IDM_TDSC_BTN				equ		2043
IDM_CHARACTERISTICS			equ		2044

IDC_MTYPE_GBOX				equ		2045
IDC_FLAGSBOX				equ		2055
IDC_SECLISTV				equ		2254


IDC_PROCLIST				equ		2257

.DATA
ofn   					OPENFILENAME <>

strFilter				db		"Executable Files (*.exe, *.dll)",0,
								"*.exe;*.dll",0,"All Files",0,"*.*",0,0 

ftTimeStamp FILETIME <>

stUTC SYSTEMTIME <>
stLocal SYSTEMTIME <>

item 			ITEMIDLIST 			<>

ProcError		db "An Error Finding has occurred!!",0
errSnapshot     db "CreateToolhelp32Snapshot failed.",0
errProcFirst    db "Process32First failed.",0


.DATA?
LVC					LV_COLUMN	<?>
LVI					LV_ITEM		<?>
hList			dd 	?
hInstance		dd	?
TargetName		db	512 dup(?)
szMD5 			db	512 dup(?)
szFileName 		db	512 dup(?)
hFile 			dd 	?
mFile 			dd 	?
mapFile 		dd 	?
sFile 			dd 	?
fSize			db	512 dup(?)
cat 			db	512 dup(?)
hWnd 			db ?
temp_buff		db	512 dup(?)

szDateString 	db 64 DUP (?)
szTimeString 	db 64 DUP (?)

hCombo			dd	?
hMachine		dd	?
FileMachine		dd 	?

tdStamp			db	512 dup(?)
tdStampX		dd	?
flagsValue		dd 	?
subSystemVal	dd  ?

hSnapshot   	HANDLE ?
ProcEnt     	PROCESSENTRY32 <>
list 			db 256 dup(?)  
