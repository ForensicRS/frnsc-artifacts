//! Which [`Artifact`] a parser reports for a ForensicArtifacts definition.

use forensic_rs::artifact::{
    Artifact, CommonArtifact, LinuxArtifacts, LinuxService, RegistryArtifacts, WebBrowsingArtifact,
    WindowsArtifacts, WindowsEvents,
};

/// The output classification for the definition `kb_name`, or `None` where there is no clear one.
/// Only definitions whose meaning is unambiguous are mapped.
pub fn output_artifact(kb_name: &str) -> Option<Artifact> {
    use RegistryArtifacts as R;
    use WindowsArtifacts as W;
    let windows = |a: WindowsArtifacts| Some(Artifact::Windows(a));
    match kb_name {
        "LinuxLastlogFile" | "LinuxUtmpFiles" | "LinuxWtmp" | "UnixUtmpFile" => {
            Some(Artifact::Linux(LinuxArtifacts::Utmp))
        }
        "LinuxAuthLogs" => Some(Artifact::Linux(LinuxArtifacts::Log("auth".to_string()))),
        "LinuxCronLogs" => Some(Artifact::Linux(LinuxArtifacts::Log("cron".to_string()))),
        "LinuxDaemonLogFiles" => Some(Artifact::Linux(LinuxArtifacts::Log("daemon".to_string()))),
        "LinuxKernelLogFiles" => Some(Artifact::Linux(LinuxArtifacts::Log("kernel".to_string()))),
        "LinuxMessagesLogFiles" => {
            Some(Artifact::Linux(LinuxArtifacts::Log("messages".to_string())))
        }
        "LinuxSysLogFiles" => Some(Artifact::Linux(LinuxArtifacts::Log("syslog".to_string()))),
        "LinuxAuditLogs" => Some(Artifact::Linux(LinuxArtifacts::Audit)),
        "LinuxSystemdJournalLogs" => Some(Artifact::Linux(LinuxArtifacts::Journal)),
        // `RootUserShellHistory` and `ShellHistoryFile` are themselves multi-shell (a `Group`,
        // or an explicit path list spanning bash/fish/sh/zsh) — ambiguous by this function's own
        // rule, so deliberately left unmapped rather than guessing one shell.
        "BashShellHistoryFile" => Some(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "bash".to_string(),
        ))),
        "ZShellHistoryFile" => Some(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "zsh".to_string(),
        ))),
        "FishShellHistoryFile" => Some(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "fish".to_string(),
        ))),
        "BourneShellHistoryFile" => Some(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "sh".to_string(),
        ))),
        "PythonHistoryFile" => Some(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "python".to_string(),
        ))),
        "MySQLHistoryFile" => Some(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "mysql".to_string(),
        ))),
        "LessHistoryFile" => Some(Artifact::Linux(LinuxArtifacts::ShellHistory(
            "less".to_string(),
        ))),
        "DebianPackagesLogFiles"
        | "DebianPackagesStatus"
        | "AptitudeLogFiles"
        | "APTSources"
        | "YumSources" => Some(Artifact::Linux(LinuxArtifacts::Packages)),
        "UnixPasswdFile"
        | "UnixShadowFile"
        | "UnixGroupsFile"
        | "UnixSudoersConfigurationFile"
        | "LinuxPasswdFile" => Some(Artifact::Linux(LinuxArtifacts::Accounts)),
        "SSHAuthorizedKeysFiles" | "SSHKnownHostsFiles" | "SSHHostPubKeys" => {
            Some(Artifact::Linux(LinuxArtifacts::Ssh))
        }
        "LinuxCronTabs" => Some(Artifact::Linux(LinuxArtifacts::Cron("crontab".to_string()))),
        "LinuxAtJobs" => Some(Artifact::Linux(LinuxArtifacts::Cron("at".to_string()))),
        "AnacronFiles" => Some(Artifact::Linux(LinuxArtifacts::Cron("anacron".to_string()))),
        "LinuxSystemdTimers" => Some(Artifact::Linux(LinuxArtifacts::Cron(
            "systemd_timer".to_string(),
        ))),
        "CronAtAllowDenyFiles" => Some(Artifact::Linux(LinuxArtifacts::Cron(
            "allow_deny".to_string(),
        ))),
        // `LinuxScheduleFiles` is itself a `Group` of `AnacronFiles`/`LinuxCronTabs`/
        // `LinuxAtJobs` — ambiguous by this function's own rule (see the shell-history comment
        // above), so deliberately left unmapped. `frnsc_linux::schedule` still covers every file
        // reached through it, classified by the real leaf definition that matched, not this one.
        "LinuxSystemdServices" => Some(Artifact::Linux(LinuxArtifacts::Service(
            LinuxService::SystemD,
        ))),
        "LinuxSysVInit" => Some(Artifact::Linux(LinuxArtifacts::Service(LinuxService::SysV))),
        "LinuxLSBInit" => Some(Artifact::Linux(LinuxArtifacts::Service(
            LinuxService::InitD,
        ))),
        "LinuxXinetd" => Some(Artifact::Linux(LinuxArtifacts::Service(
            LinuxService::Other("xinetd".to_string()),
        ))),
        // `LinuxServices` is itself a `Group` of the four service-file definitions above —
        // ambiguous by the same rule, deliberately left unmapped.
        "LinuxDistributionRelease" => Some(Artifact::Linux(LinuxArtifacts::Other(
            "distribution_release".to_string(),
        ))),
        "LinuxHostnameFile" => Some(Artifact::Linux(LinuxArtifacts::Other(
            "hostname".to_string(),
        ))),
        "LinuxTimezoneFile" | "LinuxLocalTime" => Some(Artifact::Linux(LinuxArtifacts::Other(
            "timezone".to_string(),
        ))),
        "LinuxFstab" => Some(Artifact::Linux(LinuxArtifacts::Other("fstab".to_string()))),
        // `LinuxLSBRelease` (`/etc/lsb-release`) is the same `KEY=value` shape as `os-release`,
        // so it is unambiguous even though `frnsc_linux::identity` only reaches it through the
        // `LinuxReleaseInfo` group rather than declaring it directly.
        "LinuxSystemdOSRelease" | "LinuxLSBRelease" => Some(Artifact::Linux(
            LinuxArtifacts::Other("os_release".to_string()),
        )),
        // `LinuxReleaseInfo` is itself a `Group` of `LinuxDistributionRelease`/`LinuxLSBRelease`/
        // `LinuxSystemdOSRelease` — ambiguous by the same rule, deliberately left unmapped.
        "WindowsAMCacheHveFile" => windows(W::Registry(R::AmCache)),
        "WindowsAppCompatCache" => windows(W::Registry(R::ShimCache)),
        "WindowsBackgroundActivityModeratorKeys" => windows(W::Registry(R::Bam)),
        "WindowsRunKeys" => windows(W::Registry(R::AutoRuns)),
        "WindowsServices" => windows(W::Registry(R::Services)),
        "WindowsMountedDevices" => windows(W::Registry(R::MountedDevices)),
        "WindowsWordWheelQueryRegistryKey" => windows(W::Registry(R::WordWheelQuery)),
        "WindowsPrefetchFiles" => windows(W::Prefetch),
        "WindowsXMLEventLogApplication" => windows(W::WinEvt(WindowsEvents::Application)),
        "WindowsXMLEventLogSecurity" => windows(W::WinEvt(WindowsEvents::Security)),
        "WindowsXMLEventLogSystem" => windows(W::WinEvt(WindowsEvents::System)),
        "WindowsXMLEventLogSysmon" => windows(W::WinEvt(WindowsEvents::Sysmon)),
        "WindowsXMLEventLogPowerShell" => windows(W::WinEvt(WindowsEvents::PowerShell)),
        "NTFSMFTFiles" => windows(W::MFT),
        "NTFSUSNJournal" => windows(W::UsnJrnl),
        "WindowsSystemResourceUsageMonitorDatabaseFile" => windows(W::SRU),
        "WindowsActivitiesCacheDatabase" => windows(W::Timeline),
        "WindowsUserAccessLogging" => windows(W::UAL),
        "WindowsScheduledTasks" => windows(W::ScheduledTasks),
        "ChromiumBasedBrowsersHistoryDatabaseFile"
        | "BraveBrowserHistoryDatabaseFile"
        | "VivaldiBrowserHistoryDatabaseFile"
        | "FirefoxHistory" => Some(Artifact::Common(CommonArtifact::WebBrowsing(
            WebBrowsingArtifact::BrowserHistory,
        ))),
        _ => None,
    }
}

/// Every definition name [`output_artifact`] maps.
pub const MAPPED_DEFINITIONS: &[&str] = &[
    "LinuxLastlogFile",
    "LinuxUtmpFiles",
    "LinuxWtmp",
    "UnixUtmpFile",
    "LinuxAuthLogs",
    "LinuxCronLogs",
    "LinuxDaemonLogFiles",
    "LinuxKernelLogFiles",
    "LinuxMessagesLogFiles",
    "LinuxSysLogFiles",
    "LinuxAuditLogs",
    "LinuxSystemdJournalLogs",
    "BashShellHistoryFile",
    "ZShellHistoryFile",
    "FishShellHistoryFile",
    "BourneShellHistoryFile",
    "PythonHistoryFile",
    "MySQLHistoryFile",
    "LessHistoryFile",
    "DebianPackagesLogFiles",
    "DebianPackagesStatus",
    "AptitudeLogFiles",
    "APTSources",
    "YumSources",
    "UnixPasswdFile",
    "UnixShadowFile",
    "UnixGroupsFile",
    "UnixSudoersConfigurationFile",
    "LinuxPasswdFile",
    "SSHAuthorizedKeysFiles",
    "SSHKnownHostsFiles",
    "SSHHostPubKeys",
    "LinuxCronTabs",
    "LinuxAtJobs",
    "AnacronFiles",
    "LinuxSystemdTimers",
    "CronAtAllowDenyFiles",
    "LinuxSystemdServices",
    "LinuxSysVInit",
    "LinuxLSBInit",
    "LinuxXinetd",
    "LinuxDistributionRelease",
    "LinuxHostnameFile",
    "LinuxTimezoneFile",
    "LinuxLocalTime",
    "LinuxFstab",
    "LinuxSystemdOSRelease",
    "LinuxLSBRelease",
    "WindowsAMCacheHveFile",
    "WindowsAppCompatCache",
    "WindowsBackgroundActivityModeratorKeys",
    "WindowsRunKeys",
    "WindowsServices",
    "WindowsMountedDevices",
    "WindowsWordWheelQueryRegistryKey",
    "WindowsPrefetchFiles",
    "WindowsXMLEventLogApplication",
    "WindowsXMLEventLogSecurity",
    "WindowsXMLEventLogSystem",
    "WindowsXMLEventLogSysmon",
    "WindowsXMLEventLogPowerShell",
    "NTFSMFTFiles",
    "NTFSUSNJournal",
    "WindowsSystemResourceUsageMonitorDatabaseFile",
    "WindowsActivitiesCacheDatabase",
    "WindowsUserAccessLogging",
    "WindowsScheduledTasks",
    "ChromiumBasedBrowsersHistoryDatabaseFile",
    "BraveBrowserHistoryDatabaseFile",
    "VivaldiBrowserHistoryDatabaseFile",
    "FirefoxHistory",
];
