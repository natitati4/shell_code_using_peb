.686p 
.xmm
.model flat,c
.stack  4096


; include C libraries
includelib      msvcrtd
includelib      oldnames
includelib      legacy_stdio_definitions.lib


.code
        
public  main

main proc
    
    msgBoxAcaption=    dword ptr -230h
    msgBoxAtext=    dword ptr -228h

    funcMsgBoxA=    dword ptr -220h

    addressOfMsgBoxA=   dword ptr -214h

    msgBoxAstr=     dword ptr -208h
    user32handle=   dword ptr -19Ch

    funcGetProcAddress= dword ptr -180h
    funcLoadLibraryW= dword ptr -170h

    user32str= dword ptr -164h

    funcGetProcAddrLoopIndex= dword ptr -150h
    funcLoadLibWloopIndex= dword ptr -138h

    functionFound= dword ptr -12Ch
    functionName= dword ptr -120h
    originalFirstThunk= dword ptr -114h

    firstThunk= dword ptr -108h

    index= dword ptr -0FCh
    found_library_name= dword ptr -0F0h
    AddressOfDataPointer= dword ptr -0E4h
    var_D8= dword ptr -0D8h
    current_name= dword ptr -0CCh
    datadirectory1= dword ptr -0C0h

    var_BC= dword ptr -0BCh

    first_image_descriptor= dword ptr -0B0h
    e_lfanew= dword ptr -0A4h

    imagebase1= dword ptr -8Ch
    image_base= dword ptr -80h

    addressOfGetProcAddress= dword ptr -74h
    addressOfLoadLibraryW= dword ptr -68h

    GetProcAddressStrLen= dword ptr -5Ch
    GetProcAddressStr= dword ptr -50h

    LoadLibraryWstrLen= dword ptr -2Ch
    LoadLibraryWstr= dword ptr -20h

    krnl32str= dword ptr -14h
    krnl32len= dword ptr -8

    argc= dword ptr  8
    argv= dword ptr  0Ch
    envp= dword ptr  10h

    push eax ; Save all registers
    push ebx
    push ecx
    push edx
    push esi
    push edi

    push ebp
	mov ebp, esp
	sub esp, 23Ch 			; Allocate memory on stack for local variables

    ASSUME fs:nothing

    call find_shellcode_real_address

    find_shellcode_real_address:
        pop     edi     ; store address of shellcode

    mov     esi, offset find_shellcode_real_address

    mov	    eax, LABEL_STR_KRNL32       ; get address of str
    sub     eax, esi                    ; get difference

    add     eax, edi    ; add real_shellcode_address

    mov     [ebp + krnl32str], eax    ; name KERNEL32.dll
    mov     [ebp + krnl32len], 0Ch    ; length


    mov	    eax, LABEL_STR_LOADLIBRARYW       ; get address of str
    sub     eax, esi                        ; get difference

    add     eax, edi    ; add real_shellcode_address

    mov     [ebp + LoadLibraryWstr], eax    ; name LoadLibraryW
    mov     [ebp + LoadLibraryWstrLen], 0Ch    ; length


    mov	    eax, LABEL_STR_GETPROCADDRESS       ; get address of str
    sub     eax, esi                    ; get difference

    add     eax, edi    ; add real_shellcode_address

    mov     [ebp + GetProcAddressStr], eax    ; name GetProcAddress
    mov     [ebp + GetProcAddressStrLen], 0Eh    ; length


    mov	    eax, LABEL_STR_USER32       ; get address of str
    sub     eax, esi                    ; get difference

    add     eax, edi    ; add real_shellcode_address

    mov     [ebp + user32str], eax       ; name user32.dll


    mov	    eax, LABEL_STR_MSGBOXA      ; get address of str
    sub     eax, esi                    ; get difference

    add     eax, edi    ; add real_shellcode_address

    mov     [ebp + msgBoxAstr], eax       ; name MessageBoxA


    mov	    eax, LABEL_STR_MSGBOXA_TEXT      ; get address of str
    sub     eax, esi                    ; get difference

    add     eax, edi    ; add real_shellcode_address

    mov     [ebp + msgBoxAtext], eax       ; name (whatever is in text)


    mov	    eax, LABEL_STR_MSGBOXA_CAPTION    ; get address of str
    sub     eax, esi                    ; get difference

    add     eax, edi    ; add real_shellcode_address

    mov     [ebp + msgBoxAcaption], eax       ; name (whatever is in caption)


    xor     esi, esi
    mov     eax, fs:[30h + esi] 

    ASSUME FS:ERROR


    mov     eax, [eax + 8h]         ; get the image base
    mov     [ebp + image_base], eax  ; save image base

    mov     ecx, [ebp+image_base]
    add     ecx, [eax+3Ch]          ; get to e_lfanew

    mov     [ebp+e_lfanew], ecx       ; save e_lfanew
    mov     [ebp+first_image_descriptor], 0

    mov     eax, 8

    mov     ecx, [ebp+e_lfanew]
    mov     edx, [ecx+eax+78h]      ; get to DataDirectory1 - imports directory

    mov     [ebp+DataDirectory1], edx     ; save DataDirectory[1] - imports directory

    mov     eax, [ebp+DataDirectory1]
    add     eax, [ebp+image_base]

    mov     [ebp + first_image_descriptor], eax ; save image_import_descriptor

    mov     [ebp+current_name], 0
    mov     [ebp+var_D8], 0
    mov     [ebp+AddressOfDataPointer], 0
    
    LOOP_OVER_LIBRARIES:
        mov     eax, [ebp + first_image_descriptor]

        cmp     dword ptr [eax + 0Ch], 0    ; check if name is not null
        jz      MAIN_END

        mov     ecx, [eax + 0Ch]            ; get name RVA
        add     ecx, [ebp + image_base]     ; add image base

        mov     [ebp + current_name], ecx       ; save current name
        mov     [ebp + found_library_name], 1    ; library found variable
        mov     [ebp + index], 3    ; index variable

        LIBRARY_NAME_COMPARE_LOOP:
            mov     eax, [ebp + index]
            cmp     eax, [ebp + krnl32len]

            jge     FINISH_LIBRARY_NAME_COMPARE_LOOP

            mov     eax, [ebp + krnl32str]      ; go to next char of KERNEL32.dll
            add     eax, [ebp + index]
            movsx   ecx, byte ptr [eax]

            mov     edx, [ebp + current_name]   ; go to next char of the current library name
            add     edx, [ebp + index]
            movsx   eax, byte ptr [edx]


            cmp     ecx, eax    ; compare the chars
            jz      EQUAL_CHARS

            mov    [ebp + found_library_name], 0
            jmp    FINISH_LIBRARY_NAME_COMPARE_LOOP

            EQUAL_CHARS:
                mov     eax, [ebp + index]
                add     eax, 1
                mov     [ebp + index], eax
                jmp     LIBRARY_NAME_COMPARE_LOOP

    
        FINISH_LIBRARY_NAME_COMPARE_LOOP:
            cmp     [ebp + found_library_name], 0
            
            jnz      FOUND_LIBRARY_LABEL

            mov     eax, [ebp + first_image_descriptor]
            add     eax, 14h
            mov     [ebp + first_image_descriptor], eax
            jmp     LOOP_OVER_LIBRARIES


    FOUND_LIBRARY_LABEL:

    mov     [ebp+originalFirstThunk], 0
    mov     [ebp+firstThunk], 0

    mov     eax, [ebp+first_image_descriptor]   ; get original first thunk
    mov     ecx, [ebp+image_base]
    add     ecx, [eax]
    mov     [ebp+originalFirstThunk], ecx

    mov     eax, [ebp+first_image_descriptor]   ; get first thunk
    mov     ecx, [ebp+image_base]
    add     ecx, [eax+10h]
    mov     [ebp+firstThunk], ecx

    LOOP_OVER_FUNCTIONS:
        mov     eax, [ebp+originalFirstThunk]
        cmp     dword ptr [eax], 0      ; check if not null

        jz      USE_FUNCTIONS_TO_CALL_MSGBOX

        mov     eax, [ebp+originalFirstThunk]
        mov     ecx, [ebp+image_base]
        add     ecx, [eax]      
        mov     [ebp+AddressOfDataPointer], ecx     ; AddressOfDataPointer (pIMAGE_IMPORT_BY_NAME)
        mov     eax, [ebp+AddressOfDataPointer]
        add     eax, 2      ; skip hint

        mov     [ebp+functionName], eax     ; function name

        FIND_LOADLIBRARYW:
        mov     [ebp+functionFound], 1      ; found function variable
        mov     [ebp+funcLoadLibWloopIndex], 0 ; index of llw function loop

        FIND_LOADLIBRARYW_LOOP:
            mov     eax, [ebp+funcLoadLibWloopIndex]
            cmp     eax, [ebp+loadlibrarywstrlen]   

            jge     FINISHED_LOADLIBRARYW_LOOP      ; finished len of str

            mov     eax, [ebp+loadlibrarywstr]  ; typical char by char comparison
            add     eax, [ebp+funcLoadLibWloopIndex]
            movsx   ecx, byte ptr [eax]
            mov     edx, [ebp+functionName]
            add     edx, [ebp+funcLoadLibWloopIndex]
            movsx   eax, byte ptr [edx]
            cmp     ecx, eax 

            jz      CHARS_EQUAL_LOADLIBRARYW

            mov     [ebp+functionFound], 0  ; chars not equal, stop
            jmp     FINISHED_LOADLIBRARYW_LOOP

            CHARS_EQUAL_LOADLIBRARYW:
                mov     eax, [ebp+funcLoadLibWloopIndex]
                add     eax, 1
                mov     [ebp+funcLoadLibWloopIndex], eax
                jmp     FIND_LOADLIBRARYW_LOOP


        FINISHED_LOADLIBRARYW_LOOP:

        cmp     [ebp+functionFound], 0


        jz      FIND_GETPROCADDRESS ; if not, jump to next

        mov     eax, [ebp+firstThunk] ; found function LoadLibraryW - store it's address.
        mov     ecx, [eax]
        mov     [ebp+addressOfLoadLibraryW], ecx

        FIND_GETPROCADDRESS:

        mov     [ebp+functionFound], 1
        mov     [ebp+funcGetProcAddrLoopIndex], 0

        FIND_GETPROCADDRESS_LOOP:
            mov     eax, [ebp+funcGetProcAddrLoopIndex]
            cmp     eax, [ebp+GetProcAddressStrLen]

            jge     FINISHED_GETPROCADDRESS_LOOP    ; finished len of str

            mov     eax, [ebp+GetProcAddressStr]
            add     eax, [ebp+funcGetProcAddrLoopIndex]
            movsx   ecx, byte ptr [eax]
            mov     edx, [ebp+functionName]
            add     edx, [ebp+funcGetProcAddrLoopIndex]
            movsx   eax, byte ptr [edx]
            cmp     ecx, eax

            jz      CHARS_EQUAL_GETPROCADDRESS

            mov     [ebp+functionFound], 0
            jmp     short FINISHED_GETPROCADDRESS_LOOP

            CHARS_EQUAL_GETPROCADDRESS:

            mov     eax, [ebp+funcGetProcAddrLoopIndex]
            add     eax, 1
            mov     [ebp+funcGetProcAddrLoopIndex], eax

            jmp     FIND_GETPROCADDRESS_LOOP


        FINISHED_GETPROCADDRESS_LOOP:

        cmp     [ebp+functionFound], 0
        jz      GET_NEXT_FUNC_THUNK     ; if not, jump to next (increment thunk and continue loop)

        mov     eax, [ebp+firstThunk]   ; found function GetProcAddress - store it's address.
        mov     ecx, [eax]
        mov     [ebp+addressOfGetProcAddress], ecx

        GET_NEXT_FUNC_THUNK:
            mov     eax, [ebp+originalFirstThunk]   ; inc original first thunk (functions' names)
            add     eax, 4
            mov     [ebp+originalFirstThunk], eax

            mov     eax, [ebp+firstThunk]   ; inc thunk (functions' addresses)
            add     eax, 4
            mov     [ebp+firstThunk], eax

            jmp     LOOP_OVER_FUNCTIONS     ; continue loop


    USE_FUNCTIONS_TO_CALL_MSGBOX:
        
        ; Load user32.dll, get address of MessageBoxA, and call it with the correct arguments.

        ; use LoadLibraryW to load user32.dll

        mov     eax, [ebp+addressOfLoadLibraryW]
        mov     [ebp+funcLoadLibraryW], eax

        push    [ebp + user32str]

        call    [ebp+funcLoadLibraryW]

        mov     [ebp + user32handle], eax   ; LoadLibraryA returns handle to the dll it loads.


        ; use getProcAddress to get address of MessageBoxA

        mov     eax, [ebp+addressOfGetProcAddress]
        mov     [ebp+funcGetProcAddress], eax

        push    [ebp + msgBoxAstr]
        push    [ebp + user32handle]
        
        call    [ebp + funcGetProcAddress]

        mov     [ebp + addressOfMsgBoxA], eax   ; return value is address of function - MsgBoxA in this case.
        

        ; finally, call MessageBoxA!

        mov     eax, [ebp+addressOfMsgBoxA]
        mov     [ebp+funcMsgBoxA], eax

        push    0   ;   hWnd
        push    [ebp + msgBoxAcaption]  ;   lpText
        push    [ebp + msgBoxAtext]     ;   lpCaption
        push    0   ;   uType

        call    [ebp + funcMsgBoxA]   


    MAIN_END:

    add     esp, 23Ch

    pop ebp 		; restore all registers and exit
	pop edi
    pop esi
	pop edx
	pop ecx
	pop ebx
	pop eax

	retn

    LABEL_STR_KRNL32:
        krnl32InLabel db "KERNEL32.dll", 0

    LABEL_STR_LOADLIBRARYW:
        loadLibraryWstrInLabel db "LoadLibraryA", 0 

    LABEL_STR_GETPROCADDRESS:
        getProcAddressStrInLabel db "GetProcAddress", 0

    LABEL_STR_USER32:
        user32InLabel db "user32.dll", 0

    LABEL_STR_MSGBOXA:
        msgBoxAinLabel db "MessageBoxA", 0

    LABEL_STR_MSGBOXA_TEXT:
        msgBoxAtextInLabel db "I win.", 0

    LABEL_STR_MSGBOXA_CAPTION:
        msgBoxAcaptionInLabel db "I win.", 0



main endp

        end