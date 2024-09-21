.386
.model	flat, stdcall
option	casemap :none

include consts.inc
.code
start:
	invoke	GetModuleHandle, NULL
	mov		hInstance, eax
	invoke 	InitCommonControls
	invoke	DialogBoxParam, hInstance, IDD_MAIN, 0, ADDR DlgProc, 0
	invoke	ExitProcess, eax

DlgProc	proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg==WM_INITDIALOG

	.elseif	uMsg == WM_COMMAND
		.if	wParam == IDM_OPENFILE
			mov 	ofn.lStructSize,SIZEOF ofn
			mov  	ofn.lpstrFilter, OFFSET strFilter
			mov  	ofn.lpstrFile, OFFSET szFileName
			mov  	ofn.nMaxFile,512
			mov  	ofn.Flags, 	OFN_FILEMUSTEXIST or \
								OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
								OFN_EXPLORER or OFN_HIDEREADONLY
			invoke GetOpenFileName, ADDR ofn
			.if eax==TRUE
				invoke SetDlgItemText,hWin,IDC_FiLENAME,addr szFileName
				invoke OpenPEFile,hWin,addr szFileName
				.if eax==1
					invoke SetInfos,hWin

					invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
					invoke lstrcat,addr temp_buff,addr szFileName
					invoke SetWindowText,hWin,addr temp_buff
					invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

				.elseif eax==2
					invoke SetNULL,hWin,1
					invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("Not a valid PE File.")
				.else
					invoke SetNULL,hWin,1
					invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("An error has occured!")
				.endif
			.endif
		.elseif wParam == IDM_DOSHEADER
			invoke DialogBoxParam,hInstance, IDD_DOSHEADER, hWin, addr DosHeaderDlg, 0
		.elseif wParam == IDM_FiLEHEADER
			invoke DialogBoxParam,hInstance, IDD_FiLEHEADER, hWin, addr FileHeader, 0
		.elseif wParam == IDM_OPTiONALHEADER
			invoke DialogBoxParam,hInstance, IDD_OPTHEADER, hWin, addr OptionalHeaderDlg, 0
		.elseif wParam == IDM_SECTiONS
			invoke DialogBoxParam,hInstance, IDD_SECHEADER, hWin, addr SectionHeaderDlg, 0
		.elseif wParam == IDM_DiRECTORiES
			invoke DialogBoxParam,hInstance, IDD_DIRECTORIES, hWin, addr DataDirectoriesDlg, 0
		.elseif wParam == IDM_PROCMGR
			invoke DialogBoxParam,hInstance, IDD_PROCMANAGER, hWin, addr ProcessManagerDlg, 0

		.elseif wParam ==  2244
			invoke DialogBoxParam,hInstance, IDD_SUBSYSTEM, hWin, addr SubsystemDlg, 0
		.elseif wParam ==  2245
			;invoke DialogBoxParam,hInstance, IDD_TDSTAMP, hWin, addr TimeDateStampCDlg, 0
		.elseif wParam ==  2246
			invoke DialogBoxParam,hInstance, IDD_TDSTAMP, hWin, addr TimeDateStampCDlg, 0
		.elseif wParam == 2247
			invoke DialogBoxParam,hInstance, IDD_CHARACTERISTICS, hWin, addr CharacteristicsDlg, 0
		
		.endif

	.elseif uMsg == WM_DROPFILES
		invoke DragQueryFile,wParam,NULL,addr szFileName,sizeof szFileName
		invoke DragFinish,wParam	
		invoke SetDlgItemText,hWin,IDC_FiLENAME,addr szFileName

		invoke OpenPEFile,hWin,addr szFileName
		.if eax==1
			invoke SetInfos,hWin
		.elseif eax==2
			invoke SetNULL,hWin,1
			invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("Not a valid PE File.")
		.else
			invoke SetNULL,hWin,1
			invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("An error has occured!")
		.endif

	.elseif	uMsg == WM_CLOSE
		invoke	EndDialog,hWin,0
	.endif

xor eax,eax
ret

DlgProc	endp

FileHeader proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		mov edi, mapFile
		assume edi:ptr IMAGE_DOS_HEADER
		add edi, [edi].e_lfanew
		assume edi:ptr IMAGE_NT_HEADERS
		mov esi, edi

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.FileHeader.Machine
		mov FileMachine,eax
		invoke wsprintf,addr temp_buff,chr$("%04lX"),ax
		invoke SetDlgItemText,hWin,IDC_MACHiNE,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.FileHeader.NumberOfSections
		invoke wsprintf,addr temp_buff,chr$("%04d"),ax
		invoke SetDlgItemText,hWin,IDC_NUMOFSEC,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.FileHeader.TimeDateStamp
		mov tdStampX,eax
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_TDSTAMP,addr temp_buff
		invoke lstrcpy,addr tdStamp,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.FileHeader.PointerToSymbolTable
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_POiNTER2SYMTAB,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.FileHeader.NumberOfSymbols
		invoke wsprintf,addr temp_buff,chr$("%04d"),eax
		invoke SetDlgItemText,hWin,IDC_NUMOFSYM,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
		invoke wsprintf,addr temp_buff,chr$("%04lX"),ax
		invoke SetDlgItemText,hWin,IDC_SiZEOFOPTiONALH,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.FileHeader.Characteristics
		mov flagsValue,eax
		invoke wsprintf,addr temp_buff,chr$("%04lX"),ax
		invoke SetDlgItemText,hWin,2035,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	.elseif	uMsg == WM_COMMAND
		.if wParam == IDM_MACHINETYPE_BTN
			invoke DialogBoxParam,hInstance, IDD_MACHINETYPE, hWin, addr MachineTypeDlg, 0
		.elseif wParam ==  IDM_TDSC_BTN
			invoke DialogBoxParam,hInstance, IDD_TDSTAMP, hWin, addr TimeDateStampCDlg, 0
		.elseif wParam == IDM_CHARACTERISTICS
			invoke DialogBoxParam,hInstance, IDD_CHARACTERISTICS, hWin, addr CharacteristicsDlg, 0
		.endif
	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
FileHeader endp

MachineTypeDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		mov eax,[FileMachine]
		mov ebx,eax
		invoke wsprintf,addr temp_buff,chr$("Machine Type [Current value =  0x%04lX]"),ax
		invoke SetDlgItemText,hWin,IDC_MTYPE_GBOX,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke GetDlgItem,hWin,2046
		mov hMachine,eax
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Unknown")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Intel386")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("MIPS (R2000, R3000)")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("MIPS (R4000)")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("MIPS (R10000)")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("MIPS WCE v2")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("DEC Alpha AXP")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("IBM Power PC")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Hitachi SH-3")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Hitachi SH-3E")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Hitachi SH-4")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("ARM")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Thumb")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Intel 64")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("MIPS 16")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("MIPS FPU")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("MIPS FPU 16")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Alpha 64 / AXP 64")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Tricore")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("AMD 64")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("M32R")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("EBC")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("CEF")
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("CEE")

		mov eax, [FileMachine]
		.if eax == 014Ch
			invoke SendMessage,hMachine,CB_SETCURSEL, 1, 0
		.elseif eax == 0162h
			invoke SendMessage,hMachine,CB_SETCURSEL, 2, 0
		.elseif eax == 0166h
			invoke SendMessage,hMachine,CB_SETCURSEL, 3, 0
		.elseif eax == 0168h
			invoke SendMessage,hMachine,CB_SETCURSEL, 4, 0
		.elseif eax == 0169h
			invoke SendMessage,hMachine,CB_SETCURSEL, 5, 0
		.elseif eax == 0184h
			invoke SendMessage,hMachine,CB_SETCURSEL, 6, 0
		.elseif eax == 01F0h
			invoke SendMessage,hMachine,CB_SETCURSEL, 7, 0
		.elseif eax == 01A2h
			invoke SendMessage,hMachine,CB_SETCURSEL, 8, 0
		.elseif eax == 01A4h
			invoke SendMessage,hMachine,CB_SETCURSEL, 9, 0
		.elseif eax == 01A6h
			invoke SendMessage,hMachine,CB_SETCURSEL, 10, 0
		.elseif eax == 01C0h
			invoke SendMessage,hMachine,CB_SETCURSEL, 11, 0
		.elseif eax == 01C2h
			invoke SendMessage,hMachine,CB_SETCURSEL, 12, 0	
		.elseif eax == 0200h
			invoke SendMessage,hMachine,CB_SETCURSEL, 13, 0
		.elseif eax == 0266h
			invoke SendMessage,hMachine,CB_SETCURSEL, 14, 0
		.elseif eax == 0366h
			invoke SendMessage,hMachine,CB_SETCURSEL, 15, 0
		.elseif eax == 0466h
			invoke SendMessage,hMachine,CB_SETCURSEL, 16, 0
		.elseif eax == 0284h
			invoke SendMessage,hMachine,CB_SETCURSEL, 17, 0
		.elseif eax == 0520h
			invoke SendMessage,hMachine,CB_SETCURSEL, 18, 0
		.elseif eax == 8664h
			invoke SendMessage,hMachine,CB_SETCURSEL, 19, 0
		.elseif eax == 9041h
			invoke SendMessage,hMachine,CB_SETCURSEL, 20, 0
		.elseif eax == 0EBCh
			invoke SendMessage,hMachine,CB_SETCURSEL, 21, 0
		.elseif eax == 0CEFh
			invoke SendMessage,hMachine,CB_SETCURSEL, 22, 0
		.elseif eax == 0C0EEh
			invoke SendMessage,hMachine,CB_SETCURSEL, 23, 0	
		.else
			invoke SendMessage,hMachine,CB_SETCURSEL, 0, 0
		.endif
	.elseif	uMsg == WM_COMMAND


	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
xor eax,eax
	Ret
MachineTypeDlg endp

TimeDateStampCDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke SetDlgItemText,hWin,2048,addr tdStamp
		mov eax,[tdStampX]
	;	xor eax,eax
	;	mov eax,[edi].IMAGE_NT_HEADERS.FileHeader.TimeDateStamp
		xor edx,edx
		mov ecx,10000000
		mul ecx
		add eax,0D53E8000h
		adc edx,019DB1DEh
		mov ftTimeStamp.dwLowDateTime,eax
		mov ftTimeStamp.dwHighDateTime,edx
		invoke FileTimeToSystemTime,offset ftTimeStamp,offset stLocal
		invoke GetDateFormat,LOCALE_USER_DEFAULT,NULL,offset stLocal,chr$("dddd dd MMM yyyy "),addr szDateString,64
		invoke GetTimeFormat,LOCALE_USER_DEFAULT,NULL,offset stLocal,chr$("hh:mm:ss"),addr szTimeString,64
		invoke lstrcat,addr temp_buff,addr szDateString
		invoke lstrcat,addr temp_buff,addr szTimeString
	;	invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2052,addr temp_buff
	;	invoke lstrcpy,addr tdStamp,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	.elseif	uMsg == WM_COMMAND

	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
TimeDateStampCDlg endp

CharacteristicsDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		mov eax,[flagsValue]
		invoke wsprintf,addr temp_buff,chr$("Characteristics [Current value = 0x%04lX]"),ax
		invoke SetDlgItemText,hWin,IDC_FLAGSBOX,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		mov eax,[flagsValue]
				
		xor ebx,ebx
		xor ecx,ecx
		xor edx,edx
		
		shl eax, 12
		mov bl, ah
		xor ah, ah
		shr eax, 4
		mov cl, ah
		xor ah, ah
		shr eax, 4
		mov dl, ah
		xor ah, ah
		shr eax, 4
		mov al, ah

		pushad
			Test1:
			cmp bl, 10h
			je Box1
			cmp bl, 30h
			je Box1
			cmp bl, 50h
			je Box1
			cmp bl, 70h
			je Box1
			cmp bl, 90h
			je Box1
			cmp bl, 0B0h
			je Box1
			cmp bl, 0D0h
			je Box1
			cmp bl, 0F0h
			je Box1
			jmp Test2
			Box1:
				invoke SendDlgItemMessage, hWin, 2056, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test2:	
			cmp bl, 20h
			je Box2
			cmp bl, 30h
			je Box2
			cmp bl, 60h
			je Box2
			cmp bl, 70h
			je Box2
			cmp bl, 0A0h
			je Box2
			cmp bl, 0B0h
			je Box2
			cmp bl, 0E0h
			je Box2
			cmp bl, 0F0h
			je Box2
			jmp Test3
			Box2:
				invoke SendDlgItemMessage, hWin, 2057, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test3:
			cmp bl, 40h
			je Box3
			cmp bl, 50h
			je Box3
			cmp bl, 60h
			je Box3
			cmp bl, 70h
			je Box3
			cmp bl, 0C0h
			je Box3
			cmp bl, 0D0h
			je Box3
			cmp bl, 0E0h
			je Box3
			cmp bl, 0F0h
			je Box3
			jmp Test4
			Box3:
				invoke SendDlgItemMessage, hWin, 2058, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test4:
			cmp bl, 80h
			je Box4
			cmp bl, 90h
			je Box4
			cmp bl, 0A0h
			je Box4
			cmp bl, 0B0h
			je Box4
			cmp bl, 0C0h
			je Box4
			cmp bl, 0D0h
			je Box4
			cmp bl, 0E0h
			je Box4
			cmp bl, 0F0h
			je Box4
			jmp Test10
			Box4:
				invoke SendDlgItemMessage, hWin, 2059, BM_SETCHECK,  BST_CHECKED, 0
		popad
			;//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		pushad
			Test10:
			cmp cl, 10h
			je Box10
			cmp cl, 30h
			je Box10
			cmp cl, 50h
			je Box10
			cmp cl, 70h
			je Box10
			cmp cl, 90h
			je Box10
			cmp cl, 0B0h
			je Box10
			cmp cl, 0D0h
			je Box10
			cmp cl, 0F0h
			je Box10
			jmp Test20
			Box10:
				invoke SendDlgItemMessage, hWin, 2060, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test20:	
			cmp cl, 20h
			je Box20
			cmp cl, 30h
			je Box20
			cmp cl, 60h
			je Box20
			cmp cl, 70h
			je Box20
			cmp cl, 0A0h
			je Box20
			cmp cl, 0B0h
			je Box20
			cmp cl, 0E0h
			je Box20
			cmp cl, 0F0h
			je Box20
			jmp Test40
			Box20:
				invoke SendDlgItemMessage, hWin, 2061, BM_SETCHECK,  BST_CHECKED, 0
		popad	
		pushad
			Test40:
			cmp cl, 80h
			je Box40
			cmp cl, 90h
			je Box40
			cmp cl, 0A0h
			je Box40
			cmp cl, 0B0h
			je Box40
			cmp cl, 0C0h
			je Box40
			cmp cl, 0D0h
			je Box40
			cmp cl, 0E0h
			je Box40
			cmp cl, 0F0h
			je Box40
			jmp Test100
			Box40:
				invoke SendDlgItemMessage, hWin, 2062, BM_SETCHECK,  BST_CHECKED, 0
		popad	
			;//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		pushad
			Test100:
			cmp dl, 10h
			je Box100
			cmp dl, 30h
			je Box100
			cmp dl, 50h
			je Box100
			cmp dl, 70h
			je Box100
			cmp dl, 90h
			je Box100
			cmp dl, 0B0h
			je Box100
			cmp dl, 0D0h
			je Box100
			cmp dl, 0F0h
			je Box100
			jmp Test200
			Box100:
				invoke SendDlgItemMessage, hWin, 2063, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad
			Test200:	
			cmp dl, 20h
			je Box200
			cmp dl, 30h
			je Box200
			cmp dl, 60h
			je Box200
			cmp dl, 70h
			je Box200
			cmp dl, 0A0h
			je Box200
			cmp dl, 0B0h
			je Box200
			cmp dl, 0E0h
			je Box200
			cmp dl, 0F0h
			je Box200
			jmp Test300
			Box200:
				invoke SendDlgItemMessage, hWin, 2064, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test300:
			cmp dl, 40h
			je Box300
			cmp dl, 50h
			je Box300
			cmp dl, 60h
			je Box300
			cmp dl, 70h
			je Box300
			cmp dl, 0C0h
			je Box300
			cmp dl, 0D0h
			je Box300
			cmp dl, 0E0h
			je Box300
			cmp dl, 0F0h
			je Box300
			jmp Test400
			Box300:
				invoke SendDlgItemMessage, hWin, 2065, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test400:
			cmp dl, 80h
			je Box400
			cmp dl, 90h
			je Box400
			cmp dl, 0A0h
			je Box400
			cmp dl, 0B0h
			je Box400
			cmp dl, 0C0h
			je Box400
			cmp dl, 0D0h
			je Box400
			cmp dl, 0E0h
			je Box400
			cmp dl, 0F0h
			je Box400
			jmp Test1000
			Box400:
				invoke SendDlgItemMessage, hWin, 2066, BM_SETCHECK,  BST_CHECKED, 0
		popad
			;//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		pushad
			Test1000:
			cmp al, 10h
			je Box1000
			cmp al, 30h
			je Box1000
			cmp al, 50h
			je Box1000
			cmp al, 70h
			je Box1000
			cmp al, 90h
			je Box1000
			cmp al, 0B0h
			je Box1000
			cmp al, 0D0h
			je Box1000
			cmp al, 0F0h
			je Box1000
			jmp Test2000
			Box1000:
				invoke SendDlgItemMessage, hWin, 2067, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test2000:	
			cmp al, 20h
			je Box2000
			cmp al, 30h
			je Box2000
			cmp al, 60h
			je Box2000
			cmp al, 70h
			je Box2000
			cmp al, 0A0h
			je Box2000
			cmp al, 0B0h
			je Box2000
			cmp al, 0E0h
			je Box2000
			cmp al, 0F0h
			je Box2000
			jmp Test3000
			Box2000:
				invoke SendDlgItemMessage, hWin, 2068, BM_SETCHECK,  BST_CHECKED, 0
		popad
		pushad	
			Test3000:
			cmp al, 40h
			je Box3000
			cmp al, 50h
			je Box3000
			cmp al, 60h
			je Box3000
			cmp al, 70h
			je Box3000
			cmp al, 0C0h
			je Box3000
			cmp al, 0D0h
			je Box3000
			cmp al, 0E0h
			je Box3000
			cmp al, 0F0h
			je Box3000
			jmp Test4000
			Box3000:
				invoke SendDlgItemMessage, hWin, 2069, BM_SETCHECK,  BST_CHECKED, 0
		popad	
		pushad
			Test4000:
			cmp al, 80h
			je Box4000
			cmp al, 90h
			je Box4000
			cmp al, 0A0h
			je Box4000
			cmp al, 0B0h
			je Box4000
			cmp al, 0C0h
			je Box4000
			cmp al, 0D0h
			je Box4000
			cmp ah, 0E0h
			je Box4000
			cmp ah, 0F0h
			je Box4000
			jmp Test10000
			Box4000:
				invoke SendDlgItemMessage, hWin, 2070, BM_SETCHECK,  BST_CHECKED, 0
			Test10000:
		popad


	.elseif	uMsg == WM_COMMAND

	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	RET
CharacteristicsDlg endp

OptionalHeaderDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		mov edi, mapFile
		assume edi:ptr IMAGE_DOS_HEADER
		add edi, [edi].e_lfanew
		assume edi:ptr IMAGE_NT_HEADERS32
		
		
		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.Magic
		invoke SetDlgItemText,hWin,2079,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%02lX"),[edi].OptionalHeader.MajorLinkerVersion
		invoke SetDlgItemText,hWin,2080,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%02lX"),[edi].OptionalHeader.MinorLinkerVersion
		invoke SetDlgItemText,hWin,2081,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfCode
		invoke SetDlgItemText,hWin,2082,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfInitializedData
		invoke SetDlgItemText,hWin,2083,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfUninitializedData
		invoke SetDlgItemText,hWin,2084,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.AddressOfEntryPoint
		invoke SetDlgItemText,hWin,2085,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.BaseOfCode
		invoke SetDlgItemText,hWin,2086,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.BaseOfData
		invoke SetDlgItemText,hWin,2087,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.ImageBase
		invoke SetDlgItemText,hWin,2088,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SectionAlignment
		invoke SetDlgItemText,hWin,2089,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.FileAlignment
		invoke SetDlgItemText,hWin,2090,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.MajorOperatingSystemVersion
		invoke SetDlgItemText,hWin,2091,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.MinorOperatingSystemVersion
		invoke SetDlgItemText,hWin,2092,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.MajorImageVersion
		invoke SetDlgItemText,hWin,2093,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.MinorImageVersion
		invoke SetDlgItemText,hWin,2108,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.MajorSubsystemVersion
		invoke SetDlgItemText,hWin,2111,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.MinorSubsystemVersion
		invoke SetDlgItemText,hWin,2112,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.Win32VersionValue
		invoke SetDlgItemText,hWin,2113,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfImage
		invoke SetDlgItemText,hWin,2114,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfHeaders
		invoke SetDlgItemText,hWin,2115,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.CheckSum
		invoke SetDlgItemText,hWin,2116,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.Subsystem
		invoke SetDlgItemText,hWin,2117,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].OptionalHeader.DllCharacteristics
		invoke SetDlgItemText,hWin,2118,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfStackReserve
		invoke SetDlgItemText,hWin,2119,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfStackCommit
		invoke SetDlgItemText,hWin,2120,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfHeapReserve
		invoke SetDlgItemText,hWin,2121,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.SizeOfHeapCommit
		invoke SetDlgItemText,hWin,2122,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.LoaderFlags
		invoke SetDlgItemText,hWin,2123,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].OptionalHeader.NumberOfRvaAndSizes
		invoke SetDlgItemText,hWin,2124,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
	.elseif	uMsg == WM_COMMAND

	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
OptionalHeaderDlg endp

DosHeaderDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG

		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		mov edi, mapFile
		assume edi:ptr IMAGE_DOS_HEADER
		
		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_magic
		invoke SetDlgItemText,hWin,2140,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_cblp
		invoke SetDlgItemText,hWin,2142,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_cp
		invoke SetDlgItemText,hWin,2143,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_crlc
		invoke SetDlgItemText,hWin,2144,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_cparhdr
		invoke SetDlgItemText,hWin,2145,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_minalloc
		invoke SetDlgItemText,hWin,2146,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_maxalloc
		invoke SetDlgItemText,hWin,2147,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_ss
		invoke SetDlgItemText,hWin,2148,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_sp
		invoke SetDlgItemText,hWin,2149,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff



		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_csum
		invoke SetDlgItemText,hWin,2150,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_ip
		invoke SetDlgItemText,hWin,2151,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_cs
		invoke SetDlgItemText,hWin,2152,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_lfarlc
		invoke SetDlgItemText,hWin,2153,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_ovno
		invoke SetDlgItemText,hWin,2154,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_oemid
		invoke SetDlgItemText,hWin,2155,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%04lX"),[edi].e_oeminfo
		invoke SetDlgItemText,hWin,2156,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].e_lfanew
		invoke SetDlgItemText,hWin,2157,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	.elseif	uMsg == WM_COMMAND

	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
DosHeaderDlg endp

SectionHeaderDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke GetDlgItem,hWin,IDC_SECLISTV
		mov hList,eax
		invoke InsertColumns
		;invoke AddItem, chr$("Test A1"), chr$("Test A2"), chr$("Test A3"),\
		;				chr$("Test A4"), chr$("Test A5"), chr$("Test A6")


	mov edi, mapFile
	assume edi:ptr IMAGE_DOS_HEADER
	add edi,[edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
	movzx ecx,[edi].FileHeader.NumberOfSections 
	mov ebx, [edi].OptionalHeader.SizeOfHeaders
	add edi, sizeof IMAGE_NT_HEADERS
	pushad
		

    mov LVI.imask,LVIF_TEXT  
   	mov LVI.iItem,0 
      
	;invoke SendMessage,hList,LVM_GETHEADER, 0, 0  
	;mov hHeader,eax  
	;invoke GetWindowLong, hHeader, GWL_STYLE 
	;xor eax,HDS_BUTTONS 
	;invoke SetWindowLong,hHeader, GWL_STYLE, eax  
	;mov    eax, LVS_EX_FULLROWSELECT or LVS_EX_HEADERDRAGDROP or LVS_EX_SUBITEMIMAGES
	;invoke   SendMessage, hList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, eax
	;invoke   SendMessage, hList, LVM_SETTEXTCOLOR, 0, 00000000h
	;invoke   SendMessage, hList, LVM_SETBKCOLOR, 0, 00FFFFFFh
	;invoke   SendMessage, hList, LVM_SETTEXTBKCOLOR, 0,00FFFFFFh
      	assume edi:ptr IMAGE_SECTION_HEADER 
      	
      	.while  !([edi].PointerToRawData  == ebx)
      		inc edi
      	.endw
      		
      	.while ecx>0 
      		push ecx
      			
         		mov LVI.iSubItem,0 
         		invoke RtlZeroMemory,addr temp_buff,9 
       			invoke lstrcpyn,addr temp_buff,addr [edi].Name1,8 
         		lea eax,temp_buff
         		mov LVI.pszText,eax 
         		invoke SendDlgItemMessage,hWin,IDC_SECLISTV,LVM_INSERTITEM,0,addr LVI 
         		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].Misc.VirtualSize 
         		lea eax,temp_buff 
         		mov LVI.pszText,eax 
         		inc LVI.iSubItem 
         		invoke SendDlgItemMessage,hWin,IDC_SECLISTV,LVM_SETITEM,0,addr LVI 
         		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].VirtualAddress 
         		lea eax,temp_buff 
         		mov LVI.pszText,eax 
         		inc LVI.iSubItem 
         		invoke SendDlgItemMessage,hWin,IDC_SECLISTV,LVM_SETITEM,0,addr LVI 
         		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].SizeOfRawData 
         		lea eax,temp_buff 
         		mov LVI.pszText,eax 
         		inc LVI.iSubItem 
         		invoke SendDlgItemMessage,hWin,IDC_SECLISTV,LVM_SETITEM,0,addr LVI 
         		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].PointerToRawData 
         		lea eax,temp_buff 
         		mov LVI.pszText,eax 
         		inc LVI.iSubItem 
        		invoke SendDlgItemMessage,hWin,IDC_SECLISTV,LVM_SETITEM,0,addr LVI 
         		invoke wsprintf,addr temp_buff,chr$("%08lX"),[edi].Characteristics 
         		lea eax,temp_buff
         		mov LVI.pszText,eax 
         		inc LVI.iSubItem 
        		invoke SendDlgItemMessage,hWin,IDC_SECLISTV,LVM_SETITEM,0,addr LVI 
         		inc LVI.iItem 
         		
         		pop ecx
         		dec ecx
         		add edi, sizeof IMAGE_SECTION_HEADER 
      	.endw 



	.elseif	uMsg == WM_COMMAND

	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
SectionHeaderDlg endp

DataDirectoriesDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		mov edi, mapFile
		assume edi:ptr IMAGE_DOS_HEADER
		add edi, [edi].e_lfanew
		assume edi:ptr IMAGE_NT_HEADERS32
		
	; ExportTable
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2178,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2179,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; ImportTable
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2180,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2181,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; Resource
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2182,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2183,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		xor eax,eax
		xor ebx,ebx

	; Exception
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2184,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2185,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; Security
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2186,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2187,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; Relocation
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2188,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2189,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; Debug
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2190,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2191,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; Copyright	
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COPYRIGHT * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COPYRIGHT * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2192,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2193,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; GlobalPtr
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2194,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2195,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; TLSTable
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2196,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2197,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; LoadConfig	
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2198,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2199,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; BoundImport
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2200,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2201,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; IAT
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress	
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2202,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2203,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff


	; DelayImport
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2204,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2205,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff


	; COM
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * sizeof IMAGE_DATA_DIRECTORY].VirtualAddress	
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * sizeof IMAGE_DATA_DIRECTORY].isize
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2206,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2207,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	; Reserved
		mov eax,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * sizeof IMAGE_DATA_DIRECTORY].isize+4h
		mov ebx,[edi].OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * sizeof IMAGE_DATA_DIRECTORY].isize+8h			
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,2208,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
		invoke wsprintf,addr temp_buff,chr$("%08lX"),ebx
		invoke SetDlgItemText,hWin,2209,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	.elseif	uMsg == WM_COMMAND

	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
DataDirectoriesDlg endp

SetNULL proc hWin:DWORD,B:DWORD
.if B==0
		invoke SetDlgItemText,hWin,IDC_FiLENAME,NULL
		invoke SetDlgItemText,hWin,IDC_FiLESIZE,NULL
.else
		invoke RtlZeroMemory,addr szFileName,512
		invoke RtlZeroMemory,addr fSize,512
		invoke RtlZeroMemory,addr cat,512
		invoke UnmapViewOfFile,mapFile
		invoke CloseHandle,mFile
		invoke CloseHandle,hFile
		invoke CloseHandle,sFile
.endif
RET
SetNULL endp

SetInfos proc hWin:DWORD
		mov edi, mapFile
		assume edi:ptr IMAGE_DOS_HEADER
		add edi, [edi].e_lfanew
		assume edi:ptr IMAGE_NT_HEADERS
		mov esi, edi
			
		invoke GetFileSize,hFile,0
		mov sFile,eax 
		invoke wsprintf,addr fSize,chr$("FileSize: %d bytes"),sFile
		invoke SetDlgItemText,hWin,IDC_FiLESIZE,addr fSize		
			
	;	invoke MD5Init
	;	invoke MD5Update,mapFile,sFile
	;	invoke MD5Final
	;	invoke HexEncode,eax,MD5_DIGESTSIZE,addr szMD5
	;	invoke CharLower,addr szMD5
	;	invoke lstrcat,addr cat,chr$("md5: ")
	;	invoke lstrcat,addr cat,addr szMD5
	;	invoke SetDlgItemText,hWin,IDC_FiLEHASH,addr cat

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_ENTRYPOINT,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.ImageBase
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_IMAGEBASE,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_SIZEOFIMAGE,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_BASEOFCODE,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff
				
		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.BaseOfData
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_BASEOFDATA,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_SECTIONALIGNMENT,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.FileAlignment
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_FILEALIGNMENT,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.OptionalHeader.Magic
		invoke wsprintf,addr temp_buff,chr$("%04lX"),eax
		invoke SetDlgItemText,hWin,IDC_MAGIC,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.OptionalHeader.Subsystem
		mov subSystemVal,eax
		invoke wsprintf,addr temp_buff,chr$("%04lX"),ax
		invoke SetDlgItemText,hWin,IDC_SUBSYSTEM,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.FileHeader.NumberOfSections
		invoke wsprintf,addr temp_buff,chr$("%04d"),ax
		invoke SetDlgItemText,hWin,IDC_NUMBEROFSECTIONS,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.FileHeader.TimeDateStamp
		mov tdStampX,eax
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_TIMEDATESTAMP,addr temp_buff
		invoke lstrcpy,addr tdStamp,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_SIZEOFHEADERS,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.FileHeader.Characteristics
		mov flagsValue,eax
		invoke wsprintf,addr temp_buff,chr$("%04lX"),ax
		invoke SetDlgItemText,hWin,IDC_CHARACTERISTICS,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.CheckSum
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_CHECKSUM,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov ax,[edi].IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
		invoke wsprintf,addr temp_buff,chr$("%04lX"),ax
		invoke SetDlgItemText,hWin,IDC_SIZEOFOPTIONALHEADER,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		xor eax,eax
		mov eax,[edi].IMAGE_NT_HEADERS.OptionalHeader.NumberOfRvaAndSizes
		invoke wsprintf,addr temp_buff,chr$("%08lX"),eax
		invoke SetDlgItemText,hWin,IDC_NUMBEROFRVAANDSIZES,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

	;	invoke SetNULL,hWin,1

	RET
SetInfos endp

SubsystemDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		mov eax,[subSystemVal]
		mov ebx,eax
		invoke wsprintf,addr temp_buff,chr$("Subsystem [Current value =  0x%04lX]"),ax
		invoke SetDlgItemText,hWin,2249,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke GetDlgItem,hWin,2251
		mov hMachine,eax
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Unknown")					;00
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Native")					;01
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Windows GUI")				;02
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Windows Console")			;03
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("OS/2 Console")				;05
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("POSIX Console")			;07
	;	invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Native Windows9x Driver")	;
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Windows CE")				;09
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("EFI Application")			;10
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("EFI Boot Service Device")	;11
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("EFI Runtime Driver")		;12
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("EFI ROM")					;13
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("X-Box")					;14
		invoke SendMessage,hMachine,CB_ADDSTRING,0,chr$("Boot Application")			;16

		mov eax, [subSystemVal]
		.if eax == 0001h
			invoke SendMessage,hMachine,CB_SETCURSEL, 1, 0
		.elseif eax == 0002h
			invoke SendMessage,hMachine,CB_SETCURSEL, 2, 0
		.elseif eax == 0003h
			invoke SendMessage,hMachine,CB_SETCURSEL, 3, 0
		.elseif eax == 0005h
			invoke SendMessage,hMachine,CB_SETCURSEL, 4, 0
		.elseif eax == 0007h
			invoke SendMessage,hMachine,CB_SETCURSEL, 5, 0
		.elseif eax == 0009h
			invoke SendMessage,hMachine,CB_SETCURSEL, 6, 0
		.elseif eax == 000Ah
			invoke SendMessage,hMachine,CB_SETCURSEL, 7, 0
		.elseif eax == 000Bh
			invoke SendMessage,hMachine,CB_SETCURSEL, 8, 0
		.elseif eax == 000Ch
			invoke SendMessage,hMachine,CB_SETCURSEL, 8, 0
		.elseif eax == 000Bh
			invoke SendMessage,hMachine,CB_SETCURSEL, 8, 0
		.elseif eax == 000Eh
			invoke SendMessage,hMachine,CB_SETCURSEL, 8, 0
		.elseif eax == 0010h
			invoke SendMessage,hMachine,CB_SETCURSEL, 8, 0
		.else
			invoke SendMessage,hMachine,CB_SETCURSEL, 0, 0
		.endif
	.elseif	uMsg == WM_COMMAND


	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
SubsystemDlg endp

ProcessManagerDlg proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	LOCAL lvc:LV_COLUMN

	.if uMsg == WM_INITDIALOG
		invoke lstrcpy,addr temp_buff,chr$("PEiXtract - ")
		invoke lstrcat,addr temp_buff,addr szFileName
		invoke SetWindowText,hWin,addr temp_buff
		invoke RtlZeroMemory,addr temp_buff,sizeof temp_buff

		invoke GetDlgItem,hWin,IDC_PROCLIST
		mov hList,eax



    invoke SendMessage,hList,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT or LVS_EX_FLATSB ,-1
	mov lvc.imask,LVCF_TEXT+LVCF_WIDTH
	mov lvc.pszText,CTXT("Process Name")
	mov lvc.lx,150
	invoke SendMessage,hList, LVM_INSERTCOLUMN,0,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("PID")
	mov lvc.lx,150
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 1 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("User Name")
	mov lvc.lx,130
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 2 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("Architecture")
	mov lvc.lx,76
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 3 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("Elevated")
	mov lvc.lx,90
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 4 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("Image Path")
	mov lvc.lx,250
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 5 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("Description")
	mov lvc.lx,250
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 6 ,addr lvc

		;invoke AddItem, chr$("Test A1"), chr$("Test A2"), chr$("Test A3"),\
		;				chr$("Test A4"), chr$("Test A5"), chr$("Test A6")


    mov LVI.imask,LVIF_TEXT  
   	mov LVI.iItem,0 
      

		invoke CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS,0
		.IF (eax != INVALID_HANDLE_VALUE)
			mov hSnapshot,eax
			mov [ProcEnt.dwSize],SIZEOF ProcEnt
			invoke Process32First, hSnapshot,ADDR ProcEnt
			.IF (eax)
				@@:
				;	invoke lstrcat,addr list,ADDR [ProcEnt.szExeFile]
				;	invoke lstrcat,addr list,ADDR szNewLine
					
					mov LVI.iSubItem,0 
					invoke RtlZeroMemory,addr temp_buff,9 
					lea eax,[ProcEnt.szExeFile]
					mov LVI.pszText,eax 
					invoke SendDlgItemMessage,hWin,IDC_PROCLIST,LVM_INSERTITEM,0,addr LVI 
				
					invoke wsprintf,addr temp_buff,chr$("%04d (%04lXh)"),[ProcEnt.th32ProcessID],[ProcEnt.th32ProcessID]
					lea eax,temp_buff 
					mov LVI.pszText,eax 
					inc LVI.iSubItem 
					invoke SendDlgItemMessage,hWin,IDC_PROCLIST,LVM_SETITEM,0,addr LVI 

					invoke Process32Next, hSnapshot,ADDR ProcEnt
					test eax,eax
					jnz @B
				;f	invoke MessageBox, NULL,ADDR list,chr$("Error"),MB_OK or MB_OK
			.ELSE
				invoke MessageBox, NULL,ADDR errProcFirst,NULL,MB_OK or MB_ICONERROR
			.ENDIF
				
			invoke CloseHandle, hSnapshot
		.ELSE
			invoke MessageBox, NULL,ADDR errSnapshot,NULL,MB_OK or MB_ICONERROR
		.ENDIF

	.elseif	uMsg == WM_COMMAND


	.elseif uMsg == WM_RBUTTONDOWN
		invoke SendMessage,hWin,WM_CLOSE,0,0
	.elseif uMsg == WM_CLOSE
		invoke EndDialog,hWin,0
	.endif
	xor eax,eax
	Ret
ProcessManagerDlg endp


OpenPEFile proc hWin:DWORD, szPEFile:DWORD
		invoke CreateFile,szPEFile,GENERIC_READ,FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
		.if EAX==INVALID_HANDLE_VALUE
			MOV EAX,0
			RET
		.else
			mov hFile,EAX
			invoke CreateFileMapping,hFile,0,PAGE_READONLY,0,0,0 
			.if EAX==NULL
				MOV EAX,0
				RET
			.else
				mov mFile,EAX
				invoke MapViewOfFile,mFile,FILE_MAP_READ,0,0,0
				.if EAX==NULL
					MOV EAX,0
					RET
				.else
					mov mapFile,eax
					invoke IsValidPE,hWin,mapFile
					.if EAX==NULL
						MOV EAX,2
						RET
					.endif
				.endif
			.endif
		.endif
		MOV EAX,1
		RET
OpenPEFile endp

IsValidPE proc hWin:DWORD, pMem:DWORD
		mov pMem,EAX
		.if [EAX.IMAGE_DOS_HEADER.e_magic]!=IMAGE_DOS_SIGNATURE
			MOV EAX,0
			RET
		.endif
		ADD EAX,[EAX.IMAGE_DOS_HEADER.e_lfanew]
		.if [EAX.IMAGE_NT_HEADERS.Signature]!=IMAGE_NT_SIGNATURE
			MOV EAX,0
			RET
		.endif
		MOV EAX,1
		RET
IsValidPE endp

List proc hWin:DWORD, pMsg:DWORD
	invoke SendDlgItemMessage,hWin,IDC_CHARACT,LB_ADDSTRING,0,pMsg 
	invoke SendDlgItemMessage,hWin,IDC_CHARACT,WM_VSCROLL,SB_BOTTOM,0
	Ret
List EndP

AddItem PROC itm1:DWORD,itm2:DWORD,itm3:DWORD,itm4:DWORD,itm5:DWORD,itm6:DWORD
	LOCAL Item:LV_ITEM
    mov	Item .imask,LVIF_TEXT

	mov	Item.iItem,ebx
    mov ebx,itm1
    mov	Item .pszText,ebx
    mov	Item .iSubItem,0
    invoke	SendMessage,hList,LVM_INSERTITEM,0,addr Item 

	mov	Item.iItem,eax
    inc	Item.iSubItem
    mov ebx,itm2
	mov	Item.pszText,ebx
    invoke	SendMessage,hList,LVM_SETITEM,0,addr Item 

	mov	Item.iItem,eax
    inc	Item.iSubItem
    mov ebx,itm3
	mov	Item.pszText,ebx
    invoke	SendMessage,hList,LVM_SETITEM,0,addr Item

	mov	Item.iItem,eax
    inc	Item.iSubItem
    mov ebx,itm4
	mov	Item.pszText,ebx
    invoke	SendMessage,hList,LVM_SETITEM,0,addr Item

	mov	Item.iItem,eax
    inc	Item.iSubItem
    mov ebx,itm5
	mov	Item.pszText,ebx
    invoke	SendMessage,hList,LVM_SETITEM,0,addr Item

	mov	Item.iItem,eax
    inc	Item.iSubItem
    mov ebx,itm6
	mov	Item.pszText,ebx
    invoke	SendMessage,hList,LVM_SETITEM,0,addr Item

    inc	Item.iItem
    ret   
AddItem ENDP

InsertColumns proc
	LOCAL lvc:LV_COLUMN

    invoke SendMessage,hList,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT or LVS_EX_FLATSB ,-1
	mov lvc.imask,LVCF_TEXT+LVCF_WIDTH
	mov lvc.pszText,CTXT("Name")
	mov lvc.lx,82
	invoke SendMessage,hList, LVM_INSERTCOLUMN,0,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("V. Offset")
	mov lvc.lx,76
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 1 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("V. Size")
	mov lvc.lx,76
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 2 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("R. Offset")
	mov lvc.lx,76
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 3 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("R. Size")
	mov lvc.lx,76
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 4 ,addr lvc

	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_LEFT
	mov lvc.pszText,offset CTXT("Flags")
	mov lvc.lx,76
	invoke SendMessage,hList, LVM_INSERTCOLUMN, 5 ,addr lvc
    ret
InsertColumns endp

end start

