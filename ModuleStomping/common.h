#pragma once

#include <Windows.h>

#define NT_SUCCESS ((NTSTATUS)(status) >= 0)

typedef struct _LSA_UNICODE_STRING { 
    USHORT Length;	
    USHORT MaximumLength; 
    PWSTR  Buffer; 
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES { 
    ULONG Length; 
    HANDLE RootDirectory; 
    PUNICODE_STRING ObjectName; 
    ULONG Attributes; 
    PVOID SecurityDescriptor;	
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID { 
    PVOID UniqueProcess; 
    PVOID UniqueThread; 
} CLIENT_ID, * PCLIENT_ID;


typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;