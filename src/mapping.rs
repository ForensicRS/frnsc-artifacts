//! Which [`Artifact`] a parser reports for a ForensicArtifacts definition.

use forensic_rs::artifact::{
    Artifact, CommonArtifact, RegistryArtifacts, WebBrowsingArtifact, WindowsArtifacts,
    WindowsEvents,
};

/// The output classification for the definition `kb_name`, or `None` where there is no clear one.
/// Only definitions whose meaning is unambiguous are mapped.
pub fn output_artifact(kb_name: &str) -> Option<Artifact> {
    use RegistryArtifacts as R;
    use WindowsArtifacts as W;
    let windows = |a: WindowsArtifacts| Some(Artifact::Windows(a));
    match kb_name {
        "WindowsAMCacheHveFile" => windows(W::Registry(R::AmCache)),
        "WindowsAppCompatCache" => windows(W::Registry(R::ShimCache)),
        "WindowsBackgroundActivityModeratorKeys" => windows(W::Registry(R::Bam)),
        "WindowsRunKeys" => windows(W::Registry(R::AutoRuns)),
        "WindowsServices" => windows(W::Registry(R::Services)),
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
        "ChromiumBasedBrowsersHistoryDatabaseFile" | "FirefoxHistory" => Some(Artifact::Common(
            CommonArtifact::WebBrowsing(WebBrowsingArtifact::BrowserHistory),
        )),
        _ => None,
    }
}

/// Every definition name [`output_artifact`] maps.
pub const MAPPED_DEFINITIONS: &[&str] = &[
    "WindowsAMCacheHveFile",
    "WindowsAppCompatCache",
    "WindowsBackgroundActivityModeratorKeys",
    "WindowsRunKeys",
    "WindowsServices",
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
    "FirefoxHistory",
];
