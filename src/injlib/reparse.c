#include <fltKernel.h>

#include "injlib.h"

//
// Code taken from the Windows-driver-samples github repository.
// https://github.com/Microsoft/Windows-driver-samples/blob/master/filesys/miniFilter/simrep/simrep.c
//

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#define SIMREP_STRING_TAG            'tSpR'

#if DBG

#define DEBUG_TRACE_ERROR                               0x00000001  // Errors - whenever we return a failure code
#define DEBUG_TRACE_LOAD_UNLOAD                         0x00000002  // Loading/unloading of the filter
#define DEBUG_TRACE_INSTANCES                           0x00000004  // Attach / detach of instances

#define DEBUG_TRACE_REPARSE_OPERATIONS                  0x00000008  // Operations that are performed to determine if we should return STATUS_REPARSE
#define DEBUG_TRACE_REPARSED_OPERATIONS                 0x00000010  // Operations that return STATUS_REPARSE
#define DEBUG_TRACE_REPARSED_REISSUE                    0X00000020  // Operations that need to be reissued with an IRP.

#define DEBUG_TRACE_NAME_OPERATIONS                     0x00000040  // Operations involving name provider callbacks

#define DEBUG_TRACE_RENAME_REDIRECTION_OPERATIONS       0x00000080  // Operations involving rename or hardlink redirection

#define DEBUG_TRACE_ALL_IO                              0x00000100  // All IO operations tracked by this filter

#define DEBUG_TRACE_ALL                                 0xFFFFFFFF  // All flags

#define DebugTrace(Level, Data)                     \
/*  if ((Level) & Globals.DebugLevel) {          */ \
        DbgPrint Data;                              \
/*  }                                            */

#else

#define DebugTrace(Level, Data)             {NOTHING;}

#endif

//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////

//
//  Functions that provide string allocation support
//

_When_(return==0, _Post_satisfies_(String->Buffer != NULL))
NTSTATUS
NTAPI
SimRepAllocateUnicodeString (
    _Inout_ PUNICODE_STRING String
    );

VOID
NTAPI
SimRepFreeUnicodeString (
    _Inout_ PUNICODE_STRING String
    );

BOOLEAN
NTAPI
SimRepCompareMapping(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PUNICODE_STRING MappingPath,
    _In_ BOOLEAN IgnoreCase,
    _Out_opt_ PBOOLEAN ExactMatch
    );

NTSTATUS
NTAPI
SimRepMungeName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PUNICODE_STRING SubPath,
    _In_ PUNICODE_STRING NewSubPath,
    _In_ BOOLEAN IgnoreCase,
    _In_ BOOLEAN ExactMatch,
    _Out_ PUNICODE_STRING MungedPath
    );

//
//  Functions that handle instance setup/cleanup
//

NTSTATUS
NTAPI
SimRepInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
NTAPI
SimRepInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

//
//  Functions that track operations on the volume
//

FLT_PREOP_CALLBACK_STATUS
NTAPI
SimRepPreCreate(
  _Inout_ PFLT_CALLBACK_DATA Cbd,
  _In_ PCFLT_RELATED_OBJECTS FltObjects,
  _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
  );

//
// Public functions.
//

NTSTATUS
NTAPI
SimRepInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
NTAPI
SimRepDestroy(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////

UNICODE_STRING OldName = RTL_CONSTANT_STRING(L"\\Windows\\System32\\wow64log.dll");
UNICODE_STRING NewName;  // Set up in SimRepInitialize

//
// Filter callback routines
//

FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
        FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        SimRepPreCreate,
        NULL },

    { IRP_MJ_OPERATION_END }
};

//
// Filter registration data structure
//

FLT_REGISTRATION FilterRegistration = {
    sizeof( FLT_REGISTRATION ),                     //  Size
    FLT_REGISTRATION_VERSION,                       //  Version
    0,                                              //  Flags
    NULL,                                           //  Context
    Callbacks,                                      //  Operation callbacks
    SimRepDestroy,                                  //  Filters unload routine
    SimRepInstanceSetup,                            //  InstanceSetup routine
    SimRepInstanceQueryTeardown,                    //  InstanceQueryTeardown routine
    NULL,                                           //  InstanceTeardownStart routine
    NULL,                                           //  InstanceTeardownComplete routine
    NULL,                                           //  Filename generation support callback
    NULL,                                           //  Filename normalization support callback
    NULL,                                           //  Normalize name component cleanup callback
    NULL,                                           //  Transaction notification callback
    NULL                                            //  Filename normalization support callback
};

PFLT_FILTER Filter;

PDRIVER_UNLOAD PreviousDriverDestroy;
PDRIVER_OBJECT GlobalDriverObject;

//////////////////////////////////////////////////////////////////////////
// Private functions.
//////////////////////////////////////////////////////////////////////////

_When_(return==0, _Post_satisfies_(String->Buffer != NULL))
NTSTATUS
NTAPI
SimRepAllocateUnicodeString (
    _Inout_ PUNICODE_STRING String
    )
/*++
Routine Description:
    This routine allocates a unicode string
Arguments:
    Size - the size in bytes needed for the string buffer
    String - supplies the size of the string to be allocated in the MaximumLength field
             return the unicode string
Return Value:
    STATUS_SUCCESS                  - success
    STATUS_INSUFFICIENT_RESOURCES   - failure
--*/
{

    PAGED_CODE();

    String->Buffer = ExAllocatePoolWithTag( NonPagedPool,
                                            String->MaximumLength,
                                            SIMREP_STRING_TAG );

    if (String->Buffer == NULL) {

        DebugTrace( DEBUG_TRACE_ERROR,
                    ("[SimRep]: Failed to allocate unicode string of size 0x%x\n",
                    String->MaximumLength) );

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}

VOID
NTAPI
SimRepFreeUnicodeString (
    _Inout_ PUNICODE_STRING String
    )
/*++
Routine Description:
    This routine frees a unicode string
Arguments:
    String - supplies the string to be freed
Return Value:
    None
--*/
{
    PAGED_CODE();

    if (String->Buffer) {

        ExFreePoolWithTag( String->Buffer,
                           SIMREP_STRING_TAG );
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}

BOOLEAN
NTAPI
SimRepCompareMapping(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PUNICODE_STRING MappingPath,
    _In_ BOOLEAN IgnoreCase,
    _Out_opt_ PBOOLEAN ExactMatch
    )
/*++
Routine Description:
    This routine will compare the file specified by the
    name information structure to the given mapping path
    to determine if the file is the mapping path itself
    or a child of the mapping path.
Arguments:
    NameInfo - Pointer to the name information for the file.
    MappingPath - The mapping path to compare against.
    IgnoreCase - If TRUE do a case insenstive comparison.
    ExactMatch - If supplied receives TRUE if the name exactly
                 matches the mapping path.
Return Value:
    TRUE - the file matches the mapping path
    FALSE - the file is not in the mapping path
--*/
{
    UNICODE_STRING fileName;
    BOOLEAN match;
    BOOLEAN exactMatch;

    PAGED_CODE();

    //
    //  The NameInfo parameter is assumed to have been parsed
    //

    NT_ASSERT (FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_FINAL_COMPONENT) &&
               FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_EXTENSION) &&
               FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_STREAM) &&
               FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_PARENT_DIR));

    //
    //  Point filename to the name of the file, excluding the name of the volume
    //

    NT_ASSERT( NameInfo->Name.Buffer == NameInfo->Volume.Buffer );
    NT_ASSERT( NameInfo->Name.Length >= NameInfo->Volume.Length);

    match = FALSE;
    exactMatch = FALSE;
    fileName.Buffer = Add2Ptr( NameInfo->Name.Buffer, NameInfo->Volume.Length );
    fileName.MaximumLength = NameInfo->Name.Length - NameInfo->Volume.Length;
    fileName.Length = fileName.MaximumLength;

    //
    //  Check if the filename matches this mapping entry (is the mapping
    //  entry itself or some child directory of the mapping entry)
    //

    if (RtlPrefixUnicodeString( MappingPath, &fileName, IgnoreCase )) {

        if (fileName.Length == MappingPath->Length) {

            //
            //  This path is the mapping itself
            //

            match = TRUE;

            exactMatch = TRUE;

        } else if (fileName.Buffer[(MappingPath->Length/sizeof( WCHAR ))] == OBJ_NAME_PATH_SEPARATOR) {

            //
            //  This path is a child of the mapping
            //

            match = TRUE;
        }

        //
        //  No match here means the path simply overlaps the mapping like
        //  \a\b\c overlaps \a\b\cd.txt
        //

    }

    if (ARGUMENT_PRESENT( ExactMatch )) {
        *ExactMatch = exactMatch;
    }

    return match;
}

NTSTATUS
NTAPI
SimRepMungeName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PUNICODE_STRING SubPath,
    _In_ PUNICODE_STRING NewSubPath,
    _In_ BOOLEAN IgnoreCase,
    _In_ BOOLEAN ExactMatch,
    _Out_ PUNICODE_STRING MungedPath
    )
/*++
Routine Description:
    This routine will create a new path by munginging a new subpath
    over and existing subpath.
Arguments:
    NameInfo - Pointer to the name information for the file.
    SubPath - The path to munge.
    IgnoreCase - If TRUE do a case insenstive comparison.
    ExactMatch - If TRUE only proceed if the whole path will be replaced
    MungedPath - A unicode string to received the munged path created. The
                 buffer of the string will be allocated in this function.
Return Value:
    STATUS_SUCCESS - the path was successfully munged
    STATUS_NOT_FOUND - the SubPath was not found or is not an exact match
    An appropriate NTSTATUS error otherwise.
--*/
{
    NTSTATUS status = STATUS_NOT_FOUND;
    BOOLEAN match;
    BOOLEAN exactMatch;
    USHORT length;

    PAGED_CODE();

    match = SimRepCompareMapping( NameInfo, SubPath, IgnoreCase, &exactMatch );

    if (match) {

        InjDbgPrint("[SimRep]: match=%i, exactMatch=%i\n", match, exactMatch);

        if (ExactMatch && !exactMatch) {

            goto SimRepMungeNameCleanup;
        }

        NT_ASSERT( NameInfo->Name.Length >= SubPath->Length );

        length = NameInfo->Name.Length - SubPath->Length + NewSubPath->Length;

        RtlInitUnicodeString( MungedPath, NULL );

        MungedPath->MaximumLength = (USHORT)length;

        status = SimRepAllocateUnicodeString( MungedPath );

        if (!NT_SUCCESS( status )) {

            goto SimRepMungeNameCleanup;
        }

        //
        //  Copy the volume portion of the name (part of the name preceding the matching part)
        //

        RtlCopyUnicodeString( MungedPath, &NameInfo->Volume );

        //
        //  Copy the new file name in place of the matching part of the name
        //

        status = RtlAppendUnicodeStringToString( MungedPath, NewSubPath );

        NT_ASSERT( NT_SUCCESS( status ) );

        //
        //  Copy the portion of the name following the matching part of the name
        //

        RtlCopyMemory( Add2Ptr( MungedPath->Buffer, NameInfo->Volume.Length + NewSubPath->Length ),
                       Add2Ptr( NameInfo->Name.Buffer, NameInfo->Volume.Length + SubPath->Length ),
                       NameInfo->Name.Length - NameInfo->Volume.Length - SubPath->Length );

        //
        //  Compute the final length of the new name
        //

        MungedPath->Length = length;

    }

SimRepMungeNameCleanup:

    return status;
}

NTSTATUS
NTAPI
SimRepInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++
Routine Description:
    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.
    SimRep does not attach on automatic attachment, but will attach when asked
    manually.
Arguments:
    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.
    Flags - Flags describing the reason for this attach request.
Return Value:
    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach
--*/
{

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    /*
    if ( FlagOn( Flags, FLTFL_INSTANCE_SETUP_AUTOMATIC_ATTACHMENT ) ) {

        //
        //  Do not automatically attach to a volume.
        //

        DebugTrace( DEBUG_TRACE_INSTANCES,
                    ("[Simrep]: Instance setup skipped (Volume = %p, Instance = %p)\n",
                    FltObjects->Volume,
                    FltObjects->Instance) );

        return STATUS_FLT_DO_NOT_ATTACH;
    }
    */

    //
    //  Attach on manual attachment.
    //

    DebugTrace( DEBUG_TRACE_INSTANCES,
                ("[SimRep]: Instance setup started (Volume = %p, Instance = %p)\n",
                 FltObjects->Volume,
                 FltObjects->Instance) );


    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SimRepInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++
Routine Description:
    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request. SimRep only implements it
    because otherwise calls to FltDetachVolume or FilterDetach would
    fail to detach.
Arguments:
    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.
    Flags - Indicating where this detach request came from.
Return Value:
    Returns the status of this operation.
--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DebugTrace( DEBUG_TRACE_INSTANCES,
                ("[SimRep]: Instance query teadown ended (Instance = %p)\n",
                 FltObjects->Instance) );

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
NTAPI
SimRepPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Cbd,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++
Routine Description:
    This routine does the work for SimRep sample. SimRepPreCreate is called in
    the pre-operation path for IRP_MJ_CREATE and IRP_MJ_NETWORK_QUERY_OPEN.
    The function queries the requested file name for  the create and compares
    it to the mapping path. If the file is down the "old mapping path", the
    filter checks to see if the request is fast io based. If it is we cannot
    reparse the create because fast io does not support STATUS_REPARSE.
    Instead we return FLT_PREOP_DISALLOW_FASTIO to force the io to be reissued
    on the IRP path. If the create is IRP based, then we replace the file
    object's file name field with a new path based on the "new mapping path".
    This is pageable because it could not be called on the paging path
Arguments:
    Cbd - Pointer to the filter callbackData that is passed to us.
    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.
    CompletionContext - The context for the completion routine for this
        operation.
Return Value:
    The return value is the status of the operation.
--*/
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    FLT_PREOP_CALLBACK_STATUS callbackStatus;
    UNICODE_STRING newFileName;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PAGED_CODE();

    DebugTrace( DEBUG_TRACE_ALL_IO,
                ("[SimRep]: SimRepPreCreate -> Enter (Cbd = %p, FileObject = %p)\n",
                 Cbd,
                 FltObjects->FileObject) );


    //
    // Initialize defaults
    //

    status = STATUS_SUCCESS;
    callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK; // pass through - default is no post op callback

    RtlInitUnicodeString( &newFileName, NULL );

    //
    // We only registered for this irp, so thats all we better get!
    //

    NT_ASSERT( Cbd->Iopb->MajorFunction == IRP_MJ_CREATE );

    //
    //  Check if this is a paging file as we don't want to redirect
    //  the location of the paging file.
    //

    if (FlagOn( Cbd->Iopb->OperationFlags, SL_OPEN_PAGING_FILE )) {

        DebugTrace( DEBUG_TRACE_ALL_IO,
                    ("[SimRep]: SimRepPreCreate -> Ignoring paging file open (Cbd = %p, FileObject = %p)\n",
                     Cbd,
                     FltObjects->FileObject) );

        goto SimRepPreCreateCleanup;
    }

    //
    //  We are not allowing volume opens to be reparsed in the sample.
    //

    if (FlagOn( Cbd->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN )) {

        DebugTrace( DEBUG_TRACE_ALL_IO,
                    ("[SimRep]: SimRepPreCreate -> Ignoring volume open (Cbd = %p, FileObject = %p)\n",
                     Cbd,
                     FltObjects->FileObject) );

        goto SimRepPreCreateCleanup;

    }

    //
    //  SimRep does not honor the FILE_OPEN_REPARSE_POINT create option. For a
    //  symbolic the caller would pass this flag, for example, in order to open
    //  the link for deletion. There is no concept of deleting the mapping for
    //  this filter so it is not clear what the purpose of honoring this flag
    //  would be.
    //

    //
    //  Don't reparse an open by ID because it is not possible to determine create path intent.
    //

    if (FlagOn( Cbd->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID )) {

        goto SimRepPreCreateCleanup;
    }

    /*
    if (FlagOn( Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY ) &&
        !Globals.RemapRenamesAndLinks) {

        //
        //  This is a prelude to a rename or hard link creation but the filter
        //  is NOT configured to filter these operations. To perform the operation
        //  successfully and in a consistent manner this create must not trigger
        //  a reparse. Pass through the create without attempting any redirection.
        //

        goto SimRepPreCreateCleanup;

    }
    */

    //  Get the name information.
    //

    if (FlagOn( Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY )) {

        //
        //  The SL_OPEN_TARGET_DIRECTORY flag indicates the caller is attempting
        //  to open the target of a rename or hard link creation operation. We
        //  must clear this flag when asking fltmgr for the name or the result
        //  will not include the final component. We need the full path in order
        //  to compare the name to our mapping.
        //

        ClearFlag( Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY );

        DebugTrace( DEBUG_TRACE_RENAME_REDIRECTION_OPERATIONS,
                    ("[SimRep]: SimRepPreCreate -> Clearing SL_OPEN_TARGET_DIRECTORY for %wZ (Cbd = %p, FileObject = %p)\n",
                     &nameInfo->Name,
                     Cbd,
                     FltObjects->FileObject) );


        //
        //  Get the filename as it appears below this filter. Note that we use
        //  FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY when querying the filename
        //  so that the filename as it appears below this filter does not end up
        //  in filter manager's name cache.
        //

        status = FltGetFileNameInformation( Cbd,
                                            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY,
                                            &nameInfo );

        //
        //  Restore the SL_OPEN_TARGET_DIRECTORY flag so the create will proceed
        //  for the target. The file systems depend on this flag being set in
        //  the target create in order for the subsequent SET_INFORMATION
        //  operation to proceed correctly.
        //

        SetFlag( Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY );


    } else {

        //
        //  Note that we use FLT_FILE_NAME_QUERY_DEFAULT when querying the
        //  filename. In the precreate the filename should not be in filter
        //  manager's name cache so there is no point looking there.
        //

        status = FltGetFileNameInformation( Cbd,
                                            FLT_FILE_NAME_OPENED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                            &nameInfo );
    }

    if (!NT_SUCCESS( status )) {

        DebugTrace( DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[SimRep]: SimRepPreCreate -> Failed to get name information (Cbd = %p, FileObject = %p)\n",
                     Cbd,
                     FltObjects->FileObject) );

        goto SimRepPreCreateCleanup;
    }


    DebugTrace( DEBUG_TRACE_REPARSE_OPERATIONS,
                ("[SimRep]: SimRepPreCreate -> Processing create for file %wZ (Cbd = %p, FileObject = %p)\n",
                 &nameInfo->Name,
                 Cbd,
                 FltObjects->FileObject) );

    //
    //  Parse the filename information
    //

    status = FltParseFileNameInformation( nameInfo );
    if (!NT_SUCCESS( status )) {

        DebugTrace( DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[SimRep]: SimRepPreCreate -> Failed to parse name information for file %wZ (Cbd = %p, FileObject = %p)\n",
                     &nameInfo->Name,
                     Cbd,
                     FltObjects->FileObject) );

        goto SimRepPreCreateCleanup;
    }

    //
    //  Munge the path from the old mapping to new mapping if the query overlaps
    //  the mapping path. Note: if the create is case sensitive this comparison
    //  must be as well.
    //

    status = SimRepMungeName( nameInfo,
                              &OldName,
                              &NewName,
                              !FlagOn( Cbd->Iopb->OperationFlags, SL_CASE_SENSITIVE ),
                              FALSE,
                              &newFileName);

    if (!NT_SUCCESS( status )) {

        if (status == STATUS_NOT_FOUND) {
            status = STATUS_SUCCESS;
        }

        goto SimRepPreCreateCleanup;
    }

    DebugTrace( DEBUG_TRACE_REPARSE_OPERATIONS,
                ("[SimRep]: SimRepPreCreate -> File name %wZ matches mapping. (Cbd = %p, FileObject = %p)\n"
                 "\tMapping.OldFileName = %wZ\n"
                 "\tMapping.NewFileName = %wZ\n",
                 &nameInfo->Name,
                 Cbd,
                 FltObjects->FileObject,
                 OldName,
                 NewName) );


    //
    //  Switch names
    //

    status = IoReplaceFileObjectName( Cbd->Iopb->TargetFileObject,
                                      newFileName.Buffer,
                                      newFileName.Length );

    if ( !NT_SUCCESS( status )) {

        DebugTrace( DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[SimRep]: SimRepPreCreate -> Failed to allocate string for file %wZ (Cbd = %p, FileObject = %p)\n",
                    &nameInfo->Name,
                    Cbd,
                    FltObjects->FileObject ));

        goto SimRepPreCreateCleanup;
    }

    //
    //  Set the status to STATUS_REPARSE
    //

    status = STATUS_REPARSE;


    DebugTrace( DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_REPARSED_OPERATIONS,
                ("[SimRep]: SimRepPreCreate -> Returning STATUS_REPARSE for file %wZ. (Cbd = %p, FileObject = %p)\n"
                 "\tNewName = %wZ\n",
                 &nameInfo->Name,
                 Cbd,
                 FltObjects->FileObject,
                 &newFileName) );

SimRepPreCreateCleanup:

    //
    //  Release the references we have acquired
    //

    SimRepFreeUnicodeString( &newFileName );

    if (nameInfo != NULL) {

        FltReleaseFileNameInformation( nameInfo );
    }

    if (status == STATUS_REPARSE) {

        //
        //  Reparse the open
        //

        Cbd->IoStatus.Status = STATUS_REPARSE;
        Cbd->IoStatus.Information = IO_REPARSE;
        callbackStatus = FLT_PREOP_COMPLETE;

    } else if (!NT_SUCCESS( status )) {

        //
        //  An error occurred, fail the open
        //

        DebugTrace( DEBUG_TRACE_ERROR,
                    ("[SimRep]: SimRepPreCreate -> Failed with status 0x%x \n",
                    status) );

        Cbd->IoStatus.Status = status;
        callbackStatus = FLT_PREOP_COMPLETE;
    }

    DebugTrace( DEBUG_TRACE_ALL_IO,
                ("[SimRep]: SimRepPreCreate -> Exit (Cbd = %p, FileObject = %p)\n",
                 Cbd,
                 FltObjects->FileObject) );

    return callbackStatus;

}


//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

#define SIMREP_INSTANCE_NAME        L"Reparse"
#define SIMREP_INSTANCE_ALTITUDE    L"370040"

NTSTATUS
NTAPI
SimRepInitializeRegistry(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;

    //
    // ...\CurrentControlSet\Services\[DriverName]\Instances
    //

    UNICODE_STRING InstancesSubkeyString = RTL_CONSTANT_STRING(L"\\Instances");
    UNICODE_STRING InstancesSubkeyPath;
    InstancesSubkeyPath.MaximumLength = RegistryPath->Length + InstancesSubkeyString.Length;
    Status = SimRepAllocateUnicodeString(&InstancesSubkeyPath);

    if (!NT_SUCCESS(Status))
    {
        goto ErrorInstancesSubkeyPath;
    }

    RtlAppendUnicodeStringToString(&InstancesSubkeyPath, RegistryPath);
    RtlAppendUnicodeStringToString(&InstancesSubkeyPath, &InstancesSubkeyString);

    InitializeObjectAttributes(&ObjectAttributes,
                               &InstancesSubkeyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    HANDLE InstancesSubkeyHandle;
    Status = ZwCreateKey(&InstancesSubkeyHandle,
                         KEY_ALL_ACCESS,
                         &ObjectAttributes,
                         0,
                         NULL,
                         0,
                         NULL);

    if (!NT_SUCCESS(Status))
    {
        goto ErrorInstanceSubkeyHandle;
    }

    //
    // ...\CurrentControlSet\Services\[DriverName]\Instances\Reparse
    //

    UNICODE_STRING ReparseSubkeyString = RTL_CONSTANT_STRING(L"\\" SIMREP_INSTANCE_NAME);
    UNICODE_STRING ReparseSubkeyPath;
    ReparseSubkeyPath.MaximumLength = InstancesSubkeyPath.Length + ReparseSubkeyString.Length;
    Status = SimRepAllocateUnicodeString(&ReparseSubkeyPath);

    if (!NT_SUCCESS(Status))
    {
        goto ErrorReparseSubkeyPath;
    }

    RtlAppendUnicodeStringToString(&ReparseSubkeyPath, &InstancesSubkeyPath);
    RtlAppendUnicodeStringToString(&ReparseSubkeyPath, &ReparseSubkeyString);


    InitializeObjectAttributes(&ObjectAttributes,
                               &ReparseSubkeyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    HANDLE ReparseSubkeyHandle;
    Status = ZwCreateKey(&ReparseSubkeyHandle,
                         KEY_ALL_ACCESS,
                         &ObjectAttributes,
                         0,
                         NULL,
                         0,
                         NULL);

    if (!NT_SUCCESS(Status))
    {
        goto ErrorReparseSubkeyHandle;
    }

    //
    // ...\CurrentControlSet\Services\[DriverName]\Instances\DefaultInstance
    //

    UNICODE_STRING DefaultInstanceString = RTL_CONSTANT_STRING(L"DefaultInstance");
    WCHAR DefaultInstanceValue[] = SIMREP_INSTANCE_NAME;

    Status = ZwSetValueKey(InstancesSubkeyHandle,
                           &DefaultInstanceString,
                           0,
                           REG_SZ,
                           DefaultInstanceValue,
                           sizeof(DefaultInstanceValue));

    if (!NT_SUCCESS(Status))
    {
        goto ErrorSetValueKey;
    }

    //
    // ...\CurrentControlSet\Services\[DriverName]\Instances\Reparse\Altitude
    //

    UNICODE_STRING AltitudeString = RTL_CONSTANT_STRING(L"Altitude");
    WCHAR AltitudeValue[] = SIMREP_INSTANCE_ALTITUDE;

    Status = ZwSetValueKey(ReparseSubkeyHandle,
                           &AltitudeString,
                           0,
                           REG_SZ,
                           AltitudeValue,
                           sizeof(AltitudeValue));

    if (!NT_SUCCESS(Status))
    {
        goto ErrorSetValueKey;
    }

    //
    // ...\CurrentControlSet\Services\[DriverName]\Instances\Reparse\Flags
    //

    UNICODE_STRING FlagsString = RTL_CONSTANT_STRING(L"Flags");
    ULONG FlagsValue = 0;

    Status = ZwSetValueKey(ReparseSubkeyHandle,
                           &FlagsString,
                           0,
                           REG_DWORD,
                           &FlagsValue,
                           sizeof(FlagsValue));

ErrorSetValueKey:
    ZwClose(ReparseSubkeyHandle);

ErrorReparseSubkeyHandle:
    ZwClose(InstancesSubkeyHandle);

ErrorInstanceSubkeyHandle:
    SimRepFreeUnicodeString(&ReparseSubkeyPath);

ErrorReparseSubkeyPath:
    SimRepFreeUnicodeString(&InstancesSubkeyPath);

ErrorInstancesSubkeyPath:
    return Status;
}

NTSTATUS
NTAPI
SimRepInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PFLT_REGISTRATION Registration;

    //
    //  Set path to the native DLL.
    //

    extern UNICODE_STRING InjDllPath[InjArchitectureMax];

    PUNICODE_STRING NativeInjDllPath = &InjDllPath[InjArchitectureNative];

    if (NativeInjDllPath->Length == 0) {

        InjDbgPrint("[SimRep]: Invalid native DLL path!\n");

        return STATUS_UNSUCCESSFUL;
    }

    //
    //  Initialize registry keys for the mini-filter.
    //

    status = SimRepInitializeRegistry(RegistryPath);

    if (!NT_SUCCESS(status)) {

        return status;
    }

    //
    //  Skip the drive name (such as "C:").
    //

    RtlInitUnicodeString(&NewName, InjDllPath[InjArchitectureNative].Buffer + 2);

    InjDbgPrint("[SimRep]: NewName = '%wZ'\n", &NewName);

    //
    //  Set default global configuration
    //

    Registration = &FilterRegistration;

    status = FltRegisterFilter( DriverObject,
                                Registration,
                                &Filter );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    PreviousDriverDestroy = DriverObject->DriverUnload;
    GlobalDriverObject = DriverObject;

    //
    //  Start filtering I/O
    //

    status = FltStartFiltering( Filter );

    if (!NT_SUCCESS( status )) {
        FltUnregisterFilter( Filter );
    }

    return status;
}

NTSTATUS
NTAPI
SimRepDestroy(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++
Routine Description:
    This is the unload routine for this filter driver. This is called
    when the minifilter is about to be unloaded. SimRep can unload
    easily because it does not own any IOs. When the filter is unloaded
    existing reparsed creates will continue to work, but new creates will
    not be reparsed. This is fine from the filter's perspective, but could
    result in unexpected bahavior for apps.
Arguments:
    Flags - Indicating if this is a mandatory unload.
Return Value:
    Returns the final status of this operation.
--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DebugTrace( DEBUG_TRACE_LOAD_UNLOAD,
                ("[SimRep]: Unloading driver\n") );

    if (Filter) {
        FltUnregisterFilter( Filter );

        Filter = NULL;

        if (PreviousDriverDestroy) {

            PreviousDriverDestroy( GlobalDriverObject );
            PreviousDriverDestroy = NULL;
            GlobalDriverObject = NULL;

        }
    }

    return STATUS_SUCCESS;
}
