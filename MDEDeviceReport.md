## Defender XDR Device Report
```KQL
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| project
    DeviceId,
    DeviceName,
    OSPlatform,
    OSVersion,
    DeviceType,
    MachineGroup,
    OnboardingStatus,
    DeviceManualTags,
    RegistryDeviceTag,
    LastSeen = Timestamp
//
// Defender TVM Informationen: AV Mode, Versionen, ASR, Update-Status
//
| join kind=leftouter (
    DeviceTvmInfoGathering
    | summarize arg_max(Timestamp, *) by DeviceId
    | extend AF = todynamic(AdditionalFields)
    | extend ASR = todynamic(AF["AsrConfigurationStates"])
    | project
        DeviceId,
        DataRefreshTimestamp = Timestamp,
        TVMLastSeenTime = LastSeenTime,
        AVMode = case(
            tostring(AF["AvMode"]) == "0", "Active",
            tostring(AF["AvMode"]) == "1", "Passive",
            tostring(AF["AvMode"]) == "2", "Inactive",
            tostring(AF["AvMode"]) == "4", "EDR Block Mode",
            tostring(AF["AvMode"]) == "5", "Disabled",
            tostring(AF["AvMode"]) == "6", "Not Installed",
            strcat("Unknown (", tostring(AF["AvMode"]), ")")
        ),
        AVHealth = case(
            tostring(AF["AvMode"]) == "0", "Healthy",
            tostring(AF["AvMode"]) == "1", "Attention",
            tostring(AF["AvMode"]) == "4", "Attention",
            tostring(AF["AvMode"]) == "2", "Critical",
            tostring(AF["AvMode"]) == "5", "Critical",
            tostring(AF["AvMode"]) == "6", "Critical",
            "Unknown"
        ),
        SensorHealthState = case(
            datetime_diff("day", now(), LastSeenTime) <= 1, "Active",
            datetime_diff("day", now(), LastSeenTime) <= 7, "Inactive",
            "No Heartbeat"
        ),
        SecurityIntelVersion = tostring(AF["AvSignatureVersion"]),
        EngineVersion = tostring(AF["AvEngineVersion"]),
        PlatformVersion = tostring(AF["AvPlatformVersion"]),
        EngineUpdateTime = todatetime(AF["AvEngineUpdateTime"]),
        SignatureUpdateTime = todatetime(AF["AvSignatureUpdateTime"]),
        PlatformUpdateTime = todatetime(AF["AvPlatformUpdateTime"]),
        SecurityIntelligenceUpToDate = tostring(AF["AvIsSignatureUptoDate"]),
        EngineUpToDate = tostring(AF["AvIsEngineUptodate"]),
        PlatformUpToDate = tostring(AF["AvIsPlatformUptodate"]),
        SecurityIntelPublishTime = todatetime(AF["AvSignaturePublishTime"]),
        SignatureRefreshTime = todatetime(AF["AvSignatureDataRefreshTime"]),
        ASR_ExecutableEmailContent = iff(isempty(tostring(ASR["ExecutableEmailContent"])), "N/A", tostring(ASR["ExecutableEmailContent"])),
        ASR_OfficeChildProcess = iff(isempty(tostring(ASR["OfficeChildProcess"])), "N/A", tostring(ASR["OfficeChildProcess"])),
        ASR_ExecutableOfficeContent = iff(isempty(tostring(ASR["ExecutableOfficeContent"])), "N/A", tostring(ASR["ExecutableOfficeContent"])),
        ASR_OfficeProcessInjection = iff(isempty(tostring(ASR["OfficeProcessInjection"])), "N/A", tostring(ASR["OfficeProcessInjection"])),
        ASR_ScriptExecutableDownload = iff(isempty(tostring(ASR["ScriptExecutableDownload"])), "N/A", tostring(ASR["ScriptExecutableDownload"])),
        ASR_ObfuscatedScript = iff(isempty(tostring(ASR["ObfuscatedScript"])), "N/A", tostring(ASR["ObfuscatedScript"])),
        ASR_OfficeMacroWin32ApiCalls = iff(isempty(tostring(ASR["OfficeMacroWin32ApiCalls"])), "N/A", tostring(ASR["OfficeMacroWin32ApiCalls"])),
        ASR_UntrustedExecutable = iff(isempty(tostring(ASR["UntrustedExecutable"])), "N/A", tostring(ASR["UntrustedExecutable"])),
        ASR_Ransomware = iff(isempty(tostring(ASR["Ransomware"])), "N/A", tostring(ASR["Ransomware"])),
        ASR_LsassCredentialTheft = iff(isempty(tostring(ASR["LsassCredentialTheft"])), "N/A", tostring(ASR["LsassCredentialTheft"])),
        ASR_PsexecWmiChildProcess = iff(isempty(tostring(ASR["PsexecWmiChildProcess"])), "N/A", tostring(ASR["PsexecWmiChildProcess"])),
        ASR_UntrustedUsbProcess = iff(isempty(tostring(ASR["UntrustedUsbProcess"])), "N/A", tostring(ASR["UntrustedUsbProcess"])),
        ASR_OfficeCommAppChildProcess = iff(isempty(tostring(ASR["OfficeCommAppChildProcess"])), "N/A", tostring(ASR["OfficeCommAppChildProcess"])),
        ASR_AdobeReaderChildProcess = iff(isempty(tostring(ASR["AdobeReaderChildProcess"])), "N/A", tostring(ASR["AdobeReaderChildProcess"])),
        ASR_PersistenceThroughWmi = iff(isempty(tostring(ASR["PersistenceThroughWmi"])), "N/A", tostring(ASR["PersistenceThroughWmi"])),
        ASR_VulnerableSignedDriver = iff(isempty(tostring(ASR["VulnerableSignedDriver"])), "N/A", tostring(ASR["VulnerableSignedDriver"])),
        ASR_BlockCopiedOrImpersonatedSystemTools = iff(isempty(tostring(ASR["BlockCopiedOrImpersonatedSystemTools"])), "N/A", tostring(ASR["BlockCopiedOrImpersonatedSystemTools"])),
        ASR_BlockSafeModeReboot = iff(isempty(tostring(ASR["BlockSafeModeReboot"])), "N/A", tostring(ASR["BlockSafeModeReboot"])),
        ASR_BlockWebshellCreation = iff(isempty(tostring(ASR["ASR_BlockWebshellCreation"])), "N/A", tostring(ASR["ASR_BlockWebshellCreation"]))
) on DeviceId
//
// Quick Scan Informationen from DeviceEvents
//
| join kind=leftouter (
    DeviceEvents
    | where ActionType startswith "AntivirusScan"
    | extend EventAF = todynamic(AdditionalFields)
    | extend ScanType = tostring(EventAF["ScanTypeIndex"])
    | where ScanType == "Quick"
    | extend ScanStatus = case(
        ActionType == "AntivirusScanCompleted", "Completed",
        ActionType contains "Cancel", "Cancelled",
        ActionType contains "Fail", "Failed",
        ActionType contains "Error", "Error",
        ActionType
    )
    | extend ScanError = case(
        isnotempty(tostring(EventAF["ErrorCode"])), tostring(EventAF["ErrorCode"]),
        isnotempty(tostring(EventAF["ErrorDescription"])), tostring(EventAF["ErrorDescription"]),
        "-"
    )
    | summarize arg_max(Timestamp, *) by DeviceId
    | project
        DeviceId,
        QuickScanStatus = ScanStatus,
        QuickScanError = ScanError,
        QuickScanTime = Timestamp
) on DeviceId
//
// Full Scan Informationen from DeviceEvents
//
| join kind=leftouter (
    DeviceEvents
    | where ActionType startswith "AntivirusScan"
    | extend EventAF = todynamic(AdditionalFields)
    | extend ScanType = tostring(EventAF["ScanTypeIndex"])
    | where ScanType == "Full"
    | extend ScanStatus = case(
        ActionType == "AntivirusScanCompleted", "Completed",
        ActionType contains "Cancel", "Cancelled",
        ActionType contains "Fail", "Failed",
        ActionType contains "Error", "Error",
        ActionType
    )
    | extend ScanError = case(
        isnotempty(tostring(EventAF["ErrorCode"])), tostring(EventAF["ErrorCode"]),
        isnotempty(tostring(EventAF["ErrorDescription"])), tostring(EventAF["ErrorDescription"]),
        "-"
    )
    | summarize arg_max(Timestamp, *) by DeviceId
    | project
        DeviceId,
        FullScanStatus = ScanStatus,
        FullScanError = ScanError,
        FullScanTime = Timestamp
) on DeviceId
//
// Controlled Folder Access Configuration
//
| join kind=leftouter (
    DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId == "scid-2021"
    | summarize arg_max(Timestamp, *) by DeviceId
    | join kind=leftouter (
        DeviceTvmSecureConfigurationAssessmentKB
        | project
            ConfigurationId,
            CFAConfigurationName = ConfigurationName,
            CFAConfigurationDescription = ConfigurationDescription
    ) on ConfigurationId
    | extend CFAContext = tostring(Context)
    | extend ControlledFolderAccessConfigured = case(
        tostring(IsApplicable) in ("0", "false", "False"), "N/A",
        tostring(IsCompliant) in ("1", "true", "True"), "Configured",
        tostring(IsCompliant) in ("0", "false", "False"), "Not Configured",
        "Unknown"
    )
    | extend ControlledFolderAccessSetting = case(
        CFAContext contains "Audit", "Audit",
        CFAContext contains "Enabled", "Enabled",
        CFAContext contains "Block", "Enabled",
        CFAContext contains "Disable", "Disabled",
        CFAContext contains "Off", "Disabled",
        isempty(CFAContext) and ControlledFolderAccessConfigured == "Configured", "Configured - mode not exposed",
        isempty(CFAContext) and ControlledFolderAccessConfigured == "Not Configured", "Not configured - mode not exposed",
        isempty(CFAContext) and ControlledFolderAccessConfigured == "N/A", "N/A",
        isempty(CFAContext), "Unknown",
        CFAContext
    )
    | project
        DeviceId,
        ControlledFolderAccessConfigured,
        ControlledFolderAccessSetting,
        ControlledFolderAccessContext = CFAContext,
        ControlledFolderAccessIsApplicable = tostring(IsApplicable),
        ControlledFolderAccessIsCompliant = tostring(IsCompliant),
        ControlledFolderAccessConfigurationName = CFAConfigurationName,
        ControlledFolderAccessConfigurationDescription = CFAConfigurationDescription
) on DeviceId
//
// ASR compliance information
// N/A: Not evaluated.
// Compliant only if all evaluable rules are set to "Block".
// Workstations: OfficeMacroWin32ApiCalls, OfficeCommAppChildProcess, and OfficeProcessInjection are not evaluated.
//
| extend DeviceOsType = case(
    DeviceType == "Server"or OSPlatform contains "Server", "Server",
    OSPlatform in ("Windows10","Windows11"), "Workstation",
    OSPlatform in ("macOS","Linux","Android","iOS"), "Not Supported", "Unknown"
)
| extend ASRCompliance = case(
    // macOS / Linux / iOS / Android werden nicht bewertet
    DeviceOsType == "Not Supported","N/A - Platform not supported",
    // NO TVM-/ASR-Data available
    isempty(DataRefreshTimestamp),
    "No ASR data",
    // Workstation Compliance
    // N/A will be ignored, Block or N/A are allow.
    // the three ASR Rules will be not evaluated (min. audit suffices) to ASR Compliance
    // ASR_OfficeMacroWin32ApiCalls
    // ASR_OfficeCommAppChildProcess
    // ASR_OfficeProcessInjection
    DeviceOsType == "Workstation"
    and AVMode == "Active"
    and OnboardingStatus == "Onboarded"
    and ASR_OfficeMacroWin32ApiCalls in ("Block", "Audit", "N/A")
    and ASR_OfficeProcessInjection in ("Block", "Audit", "N/A")
    and ASR_OfficeCommAppChildProcess in ("Block", "Audit", "N/A")
    and ASR_ExecutableEmailContent in ("Block", "N/A")
    and ASR_OfficeChildProcess in ("Block", "N/A")
    and ASR_ExecutableOfficeContent in ("Block", "N/A")
    and ASR_ScriptExecutableDownload in ("Block", "N/A")
    and ASR_ObfuscatedScript in ("Block", "N/A")
    and ASR_UntrustedExecutable in ("Block", "N/A")
    and ASR_Ransomware in ("Block", "N/A")
    and ASR_LsassCredentialTheft in ("Block", "N/A")
    and ASR_PsexecWmiChildProcess in ("Block", "N/A")
    and ASR_UntrustedUsbProcess in ("Block", "N/A")
    and ASR_AdobeReaderChildProcess in ("Block", "N/A")
    and ASR_PersistenceThroughWmi in ("Block", "N/A")
    and ASR_VulnerableSignedDriver in ("Block", "N/A")
    and ASR_BlockCopiedOrImpersonatedSystemTools in ("Block", "N/A")
    and ASR_BlockSafeModeReboot in ("Block", "N/A"),
    "Compliant",
    // Server Compliance
    // N/A will be ignored, Block or N/A are allow.
    DeviceOsType == "Server"
    and AVMode == "Active"
    and OnboardingStatus == "Onboarded"
    and ASR_ExecutableEmailContent in ("Block", "N/A")
    and ASR_OfficeChildProcess in ("Block", "N/A")
    and ASR_ExecutableOfficeContent in ("Block", "N/A")
    and ASR_OfficeProcessInjection in ("Block", "N/A")
    and ASR_ScriptExecutableDownload in ("Block", "N/A")
    and ASR_ObfuscatedScript in ("Block", "N/A")
    and ASR_OfficeMacroWin32ApiCalls in ("Block", "N/A")
    and ASR_UntrustedExecutable in ("Block", "N/A")
    and ASR_Ransomware in ("Block", "N/A")
    and ASR_LsassCredentialTheft in ("Block", "N/A")
    and ASR_PsexecWmiChildProcess in ("Block", "N/A")
    and ASR_UntrustedUsbProcess in ("Block", "N/A")
    and ASR_OfficeCommAppChildProcess in ("Block", "N/A")
    and ASR_AdobeReaderChildProcess in ("Block", "N/A")
    and ASR_PersistenceThroughWmi in ("Block", "N/A")
    and ASR_VulnerableSignedDriver in ("Block", "N/A")
    and ASR_BlockWebshellCreation in ("Block", "N/A")
    and ASR_BlockCopiedOrImpersonatedSystemTools in ("Block", "N/A")
    and ASR_BlockSafeModeReboot in ("Block", "N/A"),
    "Compliant",
    "Non Compliant"
)
//
// final output
//
| extend
    QuickScanStatusFinal = iff(isempty(QuickScanStatus), "No scan found", QuickScanStatus),
    QuickScanErrorFinal = iff(isempty(QuickScanError), "-", QuickScanError),
    QuickScanTimeFinal = iff(isnull(QuickScanTime), "", format_datetime(QuickScanTime, "yyyy-MM-dd HH:mm:ss")),
    FullScanStatusFinal = iff(isempty(FullScanStatus), "No scan performed", FullScanStatus),
    FullScanErrorFinal = iff(isempty(FullScanError), "-", FullScanError),
    FullScanTimeFinal = iff(isnull(FullScanTime), "", format_datetime(FullScanTime, "yyyy-MM-dd HH:mm:ss")),
    ControlledFolderAccessConfiguredFinal = iff(isempty(ControlledFolderAccessConfigured), "No assessment data", ControlledFolderAccessConfigured),
    ControlledFolderAccessSettingFinal = iff(isempty(ControlledFolderAccessSetting), "Unknown", ControlledFolderAccessSetting),
    ControlledFolderAccessContextFinal = iff(isempty(ControlledFolderAccessContext), "-", ControlledFolderAccessContext),
    ControlledFolderAccessIsApplicableFinal = iff(isempty(ControlledFolderAccessIsApplicable), "-", ControlledFolderAccessIsApplicable),
    ControlledFolderAccessIsCompliantFinal = iff(isempty(ControlledFolderAccessIsCompliant), "-", ControlledFolderAccessIsCompliant),
    ControlledFolderAccessConfigurationNameFinal = iff(isempty(ControlledFolderAccessConfigurationName), "-", ControlledFolderAccessConfigurationName),
    ControlledFolderAccessConfigurationDescriptionFinal = iff(isempty(ControlledFolderAccessConfigurationDescription), "-", ControlledFolderAccessConfigurationDescription)
| project
    DeviceId,
    ["Device name"] = DeviceName,
    ["Device group"] = MachineGroup,
    ["OS platform"] = OSPlatform,
    ["OS version"] = OSVersion,
    ["Device type"] = DeviceType,
    ["Onboarding status"] = OnboardingStatus,
    ["Manual Tags"] = DeviceManualTags,
    ["Registry Device Tag"] = RegistryDeviceTag,
    ["AV mode"] = AVMode,
    ["AV health"] = AVHealth,
    ["Sensor health"] = SensorHealthState,
    ["Security intel version"] = SecurityIntelVersion,
    ["Engine version"] = EngineVersion,
    ["Platform version"] = PlatformVersion,
    ["Quick scan status"] = QuickScanStatusFinal,
    ["Quick scan error"] = QuickScanErrorFinal,
    ["Quick scan time"] = QuickScanTimeFinal,
    ["Full scan status"] = FullScanStatusFinal,
    ["Full scan error"] = FullScanErrorFinal,
    ["Full scan time"] = FullScanTimeFinal,
    ["Last seen - telemetrie send"] = LastSeen,
    ["TVM last seen"] = TVMLastSeenTime,
    ["Data refresh timestamp"] = DataRefreshTimestamp,
    ["Engine update time"] = EngineUpdateTime,
    ["Signature update time"] = SignatureUpdateTime,
    ["Platform update time"] = PlatformUpdateTime,
    ["Security intelligence up to date"] = SecurityIntelligenceUpToDate,
    ["Engine up to date"] = EngineUpToDate,
    ["Platform up to date"] = PlatformUpToDate,
    ["Security intel publish time"] = SecurityIntelPublishTime,
    ["Signature refresh time"] = SignatureRefreshTime,
    ["Controlled Folder Access configured"] = ControlledFolderAccessConfiguredFinal,
    ["Controlled Folder Access setting"] = ControlledFolderAccessSettingFinal,
    ["Controlled Folder Access context"] = ControlledFolderAccessContextFinal,
    ["Controlled Folder Access is applicable"] = ControlledFolderAccessIsApplicableFinal,
    ["Controlled Folder Access is compliant"] = ControlledFolderAccessIsCompliantFinal,
    ["Controlled Folder Access configuration name"] = ControlledFolderAccessConfigurationNameFinal,
    ["Controlled Folder Access configuration description"] = ControlledFolderAccessConfigurationDescriptionFinal,
    ["ASR - Block executable content from email client and webmail"] = ASR_ExecutableEmailContent,
    ["ASR - Block all Office applications from creating child processes"] = ASR_OfficeChildProcess,
    ["ASR - Block Office applications from creating executable content"] = ASR_ExecutableOfficeContent,
    ["ASR - Block Office applications from injecting code into other processes"] = ASR_OfficeProcessInjection,
    ["ASR - Block JavaScript or VBScript from launching downloaded executable content"] = ASR_ScriptExecutableDownload,
    ["ASR - Block execution of potentially obfuscated scripts"] = ASR_ObfuscatedScript,
    ["ASR - Block Win32 API calls from Office macros"] = ASR_OfficeMacroWin32ApiCalls,
    ["ASR - Block executable files from running unless they meet a prevalence, age, or trusted list criterion"] = ASR_UntrustedExecutable,
    ["ASR - Use advanced protection against ransomware"] = ASR_Ransomware,
    ["ASR - Block credential stealing from the Windows local security authority subsystem"] = ASR_LsassCredentialTheft,
    ["ASR - Block process creations originating from PSExec and WMI commands"] = ASR_PsexecWmiChildProcess,
    ["ASR - Block untrusted and unsigned processes that run from USB"] = ASR_UntrustedUsbProcess,
    ["ASR - Block Office communication application from creating child processes"] = ASR_OfficeCommAppChildProcess,
    ["ASR - Block Adobe Reader from creating child processes"] = ASR_AdobeReaderChildProcess,
    ["ASR - Block persistence through WMI event subscription"] = ASR_PersistenceThroughWmi,
    ["ASR - Block abuse of exploited vulnerable signed drivers (Device)"] = ASR_VulnerableSignedDriver,
    ["ASR - Block Webshell creation for Servers"] = ASR_BlockWebshellCreation,
    ["ASR - Block use of copied or impersonated system tools"] = ASR_BlockCopiedOrImpersonatedSystemTools,
    ["ASR - Block rebooting machine in Safe Mode"] = ASR_BlockSafeModeReboot,
    ["ASR Compliance"] = ASRCompliance
| order by ["Device name"] asc

```
