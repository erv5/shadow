#ifndef shadow_plugin_h
#define shadow_plugin_h

#import <Foundation/Foundation.h>

// Canonical plugin registry — single source of truth for hook/policy
// lifecycle, built-in profile and planner. Pure Foundation; safe to link
// from any binary and from the host test harness.
// Hybrid seam: SHDWPlugin is the renamed SHDWInstallUnit (type alias kept
// for compat), SHDWPluginRegistry is the renamed SHDWInstallUnits.

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define SHDW_EXPORT __attribute__((visibility("default")))
#else
#define SHDW_EXPORT
#endif

#pragma mark - Hook IDs (plist preference keys)

#define SHDWUniversalFilesystemID             @"Universal_Filesystem"
#define SHDWUniversalURLSchemeID              @"Universal_URLScheme"
#define SHDWUniversalEnvVarsID                @"Universal_EnvVars"
#define SHDWUniversalFoundationID             @"Universal_Foundation"
#define SHDWUniversalMachBootstrapID          @"Universal_MachBootstrap"
#define SHDWUniversalIOKitID                  @"Universal_IOKit"
#define SHDWUniversalLowLevelCID              @"Universal_LowLevelC"
#define SHDWUniversalAntiDebuggingID          @"Universal_AntiDebugging"
#define SHDWUniversalCodeSigningID            @"Universal_CodeSigning"
#define SHDWUniversalDynamicLibrariesExtraID  @"Universal_DynamicLibrariesExtra"
#define SHDWUniversalSyscallID                @"Universal_Syscall"
#define SHDWUniversalSandboxID                @"Universal_Sandbox"
#define SHDWUniversalMemoryID                 @"Universal_Memory"
#define SHDWUniversalHideAppsID               @"Universal_HideApps"
#define SHDWUniversalPseudoSandboxModeID      @"Universal_PseudoSandboxMode"
#define SHDWUniversalPathRewriteID            @"Universal_PathRewrite"
#define SHDWUniversalMemoryLevelHidingID      @"Universal_MemoryLevelHiding"
#define SHDWUniversalHarnessBaselineID        @"Universal_HarnessBaseline"

#define SHDWAdapterDeviceCheckID              @"Adapter_DeviceCheck"
#define SHDWAdapterFreeRASPID                 @"Adapter_FreeRASP"
#define SHDWAdapterDeviceSecurityKitID        @"Adapter_DeviceSecurityKit"
#define SHDWAdapterIOSSecuritySuiteID         @"Adapter_IOSSecuritySuite"
#define SHDWAdapterDTTJailbreakDetectionID    @"Adapter_DTTJailbreakDetection"
#define SHDWAdapterSafeDeviceID               @"Adapter_SafeDevice"
#define SHDWAdapterJailMonkeyID               @"Adapter_JailMonkey"
#define SHDWAdapterBATJailbreakGuardID        @"Adapter_BATJailbreakGuard"

#define SHDWHookLibraryID          @"HK_Library"
#define SHDWAppEnabledID           @"App_Enabled"
// Read-only migration keys. New settings write only App_Enabled.
#define SHDWGlobalEnabledID        @"Global_Enabled"
#define SHDWAppDisabledID          @"App_Disabled"
#define SHDWSingleToggleMigrationID @"SingleToggleMigrated"

// Aggressive detector neutralization. Live scalar, resolved like activation:
// a global default (root scalar) with an optional per-app override (same key
// inside the app dict; absent = follow global). When on, disable-style adapter
// paths (which force a detector's check result to "clean") activate in addition
// to the natural, stock-shaped bypasses. Off = natural bypasses only, so the
// process looks like a pristine stock device rather than one actively fighting
// a named detector. Only meaningful when the app is enabled.
#define SHDWDetectorAggressiveID   @"Detector_Aggressive"

// Per-app svc-scan policy. When on for an app, ShadowCore scans every added
// image for inline svc sites synchronously in dyld's add-image callback
// instead of queueing for the async drainer, so a detector's raw-svc probes
// are intercepted before its initializers can run. Costs launch time on
// image-heavy apps; intended for detectors that probe during the async window
// (BShield-class). Per-app only: read from the app dict by ShadowCore at init.
#define SHDWUniversalSvcSyncID     @"Universal_SvcSync"

// Per-app termination veto. When on for an app, raw termination syscalls
// (SYS_exit; kill(self, SIGKILL/SIGTERM/SIGABRT/SIGQUIT)) issued from
// app-owned svc sites are swallowed with the kernel-success convention faked,
// so a RASP error flow cannot terminate the process through them. Force-quit
// and jetsam still work (they never pass through these sites). Per-app only:
// read from the app dict by ShadowCore at init.
#define SHDWUniversalSvcExitVetoID @"Universal_SvcExitVeto"

// Per-app JIT-pool coverage. When on for an app, anonymous private executable
// regions (the MAP_JIT syscall-stub tables BShield-class detectors generate
// at runtime) are swept for inline svc sites, and each site is redirected
// through the svc trampoline — so a JIT'd probe gets the same path policy and
// a JIT'd exit the same veto as an image-based one. Costs a periodic region
// walk. Per-app only: read from the app dict by ShadowCore at init.
#define SHDWUniversalSvcPoolsID    @"Universal_SvcPools"

// Per-app deferred tweak loads. An array of dylib paths to dlopen six seconds
// after launch, once detector bring-up has settled — for tweaks whose
// initializers crash or trip a detector when they run inside the launch
// window (rstweak-class identity spoofers against BShield-class RASP). The
// load runs from ShadowCore (a trusted loader image). Per-app only: read
// from the app dict by ShadowCore at init.
#define SHDWUniversalDeferredLoadID @"Universal_DeferredLoad"

// Resolve the effective aggressive-neutralization state for an app: the per-app
// override if present, else the global default. Mirrors SHDWApplicationEnabled's
// global-fallback shape.
static inline BOOL SHDWDetectorAggressiveEnabled(NSDictionary* appSettings,
                                                 BOOL globalAggressive) {
    id appValue = appSettings[SHDWDetectorAggressiveID];
    return appValue ? [appValue boolValue] : globalAggressive;
}

static inline BOOL SHDWApplicationEnabled(NSDictionary* appSettings,
                                          BOOL legacyGlobalEnabled,
                                          BOOL singleToggleMigrated,
                                          BOOL forceEnabled) {
    if(forceEnabled) {
        return YES;
    }
    if([appSettings[SHDWAppDisabledID] boolValue]) {
        return NO;
    }
    // Before migration, App_Enabled=NO meant "follow global" rather than off.
    if(!singleToggleMigrated && legacyGlobalEnabled) {
        return YES;
    }
    id appEnabled = appSettings[SHDWAppEnabledID];
    return appEnabled ? [appEnabled boolValue] : legacyGlobalEnabled;
}

#pragma mark - Lifecycle phases

typedef NS_ENUM(NSInteger, SHDWLifecyclePhase) {
    SHDWPhaseAlways = 0,
    SHDWPhaseTier1,
    SHDWPhaseTier2,
    SHDWPhaseUIKit,
    SHDWPhaseEscalation,
    SHDWPhaseSDKFallback,
};

typedef NS_ENUM(NSInteger, SHDWLifecycleEvent) {
    SHDWEventCtor = 0,
    SHDWEventUIKitLoaded,
    SHDWEventDetectorEscalation,
    SHDWEventSDKFallback,
};

#pragma mark - Native HookKit request capabilities

typedef NS_OPTIONS(NSUInteger, SHDWCapabilities) {
    SHDWCapMessage   = 1 << 0,
    SHDWCapFunction  = 1 << 1,
    SHDWCapInline    = 1 << 2,
    SHDWCapPrivateSym = 1 << 3,
};

#pragma mark - Plugin (renamed InstallUnit)

typedef NS_ENUM(NSInteger, SHDWCapabilityKind) {
    SHDWCapabilityNone = 0,
    SHDWCapabilityMessage,
    SHDWCapabilityFunction,
    SHDWCapabilitySymlookup,
    SHDWCapabilityPrivateSym,
};

// One installable plugin = one installer call with one backend role.
// Renamed from SHDWInstallUnit; pluginID is canonical, unitID is compat alias via macro.
typedef struct {
    const char* pluginID;
    NSString* prefKey;
    SHDWLifecyclePhase phase;
    SHDWCapabilityKind capability;
    unsigned ctorInstall : 1;
    unsigned verify : 1;
} SHDWPlugin;
#ifndef unitID
#define unitID pluginID
#endif

// Backward-compat alias — single source, no duplication.
typedef SHDWPlugin SHDWInstallUnit;

#pragma mark - Registry (renamed InstallUnits)

SHDW_EXPORT const SHDWPlugin* SHDWPluginRegistry(NSUInteger* outCount);
// Compat: old name forwards to new impl
SHDW_EXPORT const SHDWInstallUnit* SHDWInstallUnits(NSUInteger* outCount);

#pragma mark - Built-in profile

SHDW_EXPORT NSDictionary<NSString*, id>* SHDWDefaultHookSettings(void);

#pragma mark - Capability metadata

SHDW_EXPORT NSString* SHDWHookGroupCapabilityKind(NSString* groupID);

#pragma mark - Planner (pure)

SHDW_EXPORT NSArray<NSString*>* SHDWPluginPlan(NSDictionary<NSString*, id>* prefs,
                                               SHDWCapabilities caps,
                                               SHDWLifecycleEvent event);
// Compat
SHDW_EXPORT NSArray<NSString*>* SHDWHookPlan(NSDictionary<NSString*, id>* prefs,
                                             SHDWCapabilities caps,
                                             SHDWLifecycleEvent event);

#endif // shadow_plugin_h
