.code
AsciiToHex proc uses esi ebx ecx Ascii:DWORD, Digit:DWORD
	mov ebx, Ascii
	mov ecx, Digit
	xor esi, esi
	lea eax, dword ptr[ebx]
	
		@Start:
			test ecx,ecx
			jz @ret
			movzx ebx,byte ptr [eax]
			cmp ebx, 39h
			ja @Letters
			sub ebx, 30h
			jmp @Convert
		@Letters:
			sub ebx, 37h
		@Convert:	
			test esi, esi
			jnz @f
			add esi, ebx
			inc eax
			dec ecx
			jmp @Start
		@@:
			shl esi, 4
			add esi, ebx
			inc eax
			dec ecx
			jmp @Start
		@ret:
		
	mov eax, esi	
	Ret
AsciiToHex endp

comment /*
AsciiLength proc uses ebx ecx  Ascii:DWORD, Digit:DWORD
	mov ebx, Ascii
	mov ecx, Digit
	lea eax, dword ptr[ebx]
	
		@@:
			test ecx,ecx
			jz @ret
			movzx ebx,byte ptr [eax]
			cmp ebx, 30h
			jne @ret
			inc eax
			dec ecx
			jmp @b
		@ret:
		
	mov eax, ecx	
	Ret
AsciiLength endp

OffsetToRVA proc dOffset:DWORD
	mov edi,pMem
	assume edi:ptr IMAGE_DOS_HEADER
	add edi,[edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
	mov esi,dOffset
	mov edx,edi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[edi].FileHeader.NumberOfSections
	movzx ecx, cx
	mov ebx, [edi].OptionalHeader.SizeOfHeaders
	assume edx:ptr IMAGE_SECTION_HEADER
	
	.while  !([edx].PointerToRawData  == ebx)
      		inc edx
      	.endw
      	
	.while ecx>0	
		.if esi>=[edx].PointerToRawData
		
			pushad
			invoke lstrcpyn,addr buffer2,addr [edx].Name1, 8
			popad
			
			mov eax,[edx].PointerToRawData
			add eax,[edx].SizeOfRawData
			.if esi<eax
				mov eax,[edx].PointerToRawData
				sub esi,eax	
				mov eax,[edx].VirtualAddress
				add eax,esi	
				assume edx:nothing
				assume edi:nothing
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
	.endw
	
	assume edx:nothing
	assume edi:nothing
	mov eax,esi
	Ret
OffsetToRVA endp
RVAToOffset proc RVA:DWORD
	mov edi,pMem
	assume edi:ptr IMAGE_DOS_HEADER
	add edi,[edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
	mov esi,RVA
	mov edx,edi
	add edx,sizeof IMAGE_NT_HEADERS
	mov cx,[edi].FileHeader.NumberOfSections
	movzx ecx, cx
	mov ebx, [edi].OptionalHeader.SizeOfHeaders
	assume edx:ptr IMAGE_SECTION_HEADER
	
	.while  !([edx].PointerToRawData  == ebx)
      		inc edx
      	.endw
 
	.while ecx>0	
		.if esi>=[edx].VirtualAddress
		
			pushad
			mov lpSectionNumber, ecx
			movzx eax,  [edx].Name1
			mov lpIsSectionNameEmpty, eax
			invoke lstrcpyn,addr buffer2,addr [edx].Name1, 8
			popad
			
			mov eax,[edx].VirtualAddress
			add eax,[edx].SizeOfRawData
			.if esi<eax
				mov eax,[edx].VirtualAddress
				sub esi,eax	
				mov eax,[edx].PointerToRawData
				add eax,esi
				assume edx:nothing
				assume edi:nothing
				ret
			.endif
		.endif
		add edx,sizeof IMAGE_SECTION_HEADER
		dec ecx
	.endw
	
	assume edx:nothing
	assume edi:nothing
	mov eax,esi
	ret
RVAToOffset endp

RVAToVA proc RVA:DWORD

	mov edi,pMem
	assume edi:ptr IMAGE_DOS_HEADER
	add edi,[edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
	mov ebx,[edi].OptionalHeader.ImageBase
	mov eax,RVA
	add eax, ebx
	
	assume edi:nothing
	ret
RVAToVA endp

VAToRVA proc VA:DWORD

	mov edi,pMem
	assume edi:ptr IMAGE_DOS_HEADER
	add edi,[edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
	mov ebx,[edi].OptionalHeader.ImageBase
	mov eax,VA
	sub eax, ebx
	
	assume edi:nothing
	ret
VAToRVA endp

VAToOffset proc VA:DWORD 
	
	mov eax,VA
	invoke VAToRVA,eax
	invoke RVAToOffset,eax
	
	ret
VAToOffset endp
OffsetToVA proc dOffset:DWORD

	mov eax, dOffset
	invoke OffsetToRVA, eax
	invoke RVAToVA, eax
	
	Ret
OffsetToVA endp

*/