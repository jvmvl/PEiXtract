		invoke DragQueryFile,wParam,NULL,addr szFileName,sizeof szFileName
		invoke DragFinish,wParam	
								
		invoke CreateFile,addr szFileName,GENERIC_READ,FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
		.if eax!=INVALID_HANDLE_VALUE
			mov hFile,eax
			invoke CreateFileMapping,hFile,0,PAGE_READONLY,0,0,0 
			.if eax!=NULL
				mov mFile,eax
				invoke MapViewOfFile,mFile,FILE_MAP_READ,0,0,0
				.if eax!=NULL
					mov mapFile,eax
					.if [eax.IMAGE_DOS_HEADER.e_magic]==IMAGE_DOS_SIGNATURE
						add eax,[eax.IMAGE_DOS_HEADER.e_lfanew]
						.if [eax.IMAGE_NT_HEADERS.Signature]==IMAGE_NT_SIGNATURE
							mov edi, mapFile
							assume edi:ptr IMAGE_DOS_HEADER
							add edi, [edi].e_lfanew
							assume edi:ptr IMAGE_NT_HEADERS
							mov esi, edi
									
							invoke GetFileSize,hFile,0
							mov sFile,eax 
							invoke wsprintf,addr fSize,chr$("FileSize: %d bytes"),sFile
								
							invoke MD5Init
							invoke MD5Update,mapFile,sFile
							invoke MD5Final
							invoke HexEncode,eax,MD5_DIGESTSIZE,addr szMD5
							invoke CharLower,addr szMD5
							invoke lstrcat,addr cat,chr$("md5: ")
							invoke lstrcat,addr cat,addr szMD5
								
							invoke SetDlgItemText,hWin,IDC_FiLENAME,addr szFileName
							invoke SetDlgItemText,hWin,IDC_FiLESIZE,addr fSize
							invoke SetDlgItemText,hWin,IDC_FiLEHASH,addr cat
							call ClearA
						.else 
							invoke SetDlgItemText,hWin,IDC_FiLENAME,NULL
							invoke SetDlgItemText,hWin,IDC_FiLESIZE,NULL
							invoke SetDlgItemText,hWin,IDC_FiLEHASH,NULL
							call ClearA
							invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("Not a valid PE file!")
						.endif
					.else
							invoke SetDlgItemText,hWin,IDC_FiLENAME,NULL
							invoke SetDlgItemText,hWin,IDC_FiLESIZE,NULL
							invoke SetDlgItemText,hWin,IDC_FiLEHASH,NULL
							call ClearA
							invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("Not a valid PE file!")
					.endif
					call ClearA
				.else
					invoke SetDlgItemText,hWin,IDC_FiLENAME,NULL
					invoke SetDlgItemText,hWin,IDC_FiLESIZE,NULL
					invoke SetDlgItemText,hWin,IDC_FiLEHASH,NULL
					call ClearA
					invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("MapViewOfFile Error")
				.endif
			.else
				invoke SetDlgItemText,hWin,IDC_FiLENAME,NULL
				invoke SetDlgItemText,hWin,IDC_FiLESIZE,NULL
				invoke SetDlgItemText,hWin,IDC_FiLEHASH,NULL
				call ClearA
				invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("CreateFileMapping Error")
			.endif
			call ClearA										
		.else
			invoke SetDlgItemText,hWin,IDC_FiLENAME,NULL
			invoke SetDlgItemText,hWin,IDC_FiLESIZE,NULL
			invoke SetDlgItemText,hWin,IDC_FiLEHASH,NULL
			call ClearA
			invoke SetDlgItemText,hWin,IDC_FiLENAME,chr$("Unable to open target file!")
		.endif