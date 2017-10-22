
.data

public AiDeliverApcLabelBegin
public AiDeliverApcLabelEnd

public AiDeliverApcLabelSize
AiDeliverApcLabelSize dq AiDeliverApcLabelEnd-AiDeliverApcLabelBegin

;                                                                     ;
; ------------------------------------------------------------------- ;
;                            CODE  SECTION                            ;
; ------------------------------------------------------------------- ;
;                                                                     ;

.CODE

        ;
        ; NTSTATUS
        ; NTAPI
        ; AiDeliverApc(
        ;   _In_ PVOID NormalContext   // rcx
        ;   _In_ PVOID SystemArgument1 // rdx (LdrLoadDll)
        ;   _In_ PVOID SystemArgument2 // r8
        ;   );
        ;

    AiDeliverApc PROC PUBLIC

        ;
        ; NTSTATUS
        ; NTAPI
        ; LdrLoadDll(
        ;   _In_opt_ PWSTR SearchPath OPTIONAL,
        ;   _In_opt_ PULONG DllCharacteristics OPTIONAL,
        ;   _In_     PUNICODE_STRING DllName,
        ;   _Out_    PVOID *BaseAddress
        ;   );
        ;
        ; LdrLoadDll(
        ;   NULL,           // rcx
        ;   0,              // rdx
        ;   &DllName,       // r8
        ;   &BaseAddress);  // r9
        ;

        AiDeliverApcLabelBegin::

        int 3
        sub rsp, 40

        mov r10, rdx
        lea r9, [rsp]
        lea r8, [DllName]
        xor rdx, rdx
        xor rcx, rcx
        call r10

        add rsp, 40

        ret

        AiDeliverApcLabelEnd::
          DllName db ?

    AiDeliverApc ENDP

END
