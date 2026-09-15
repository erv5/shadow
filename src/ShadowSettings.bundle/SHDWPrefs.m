#import "SHDWPrefs.h"

#import <UIKit/UIKit.h>
#import <Shadow/HookConfiguration.h>
#import <Shadow/JBPath.h>
#import <Preferences/PSSpecifier.h>

void SHDWLocalizeSpecifiers(NSArray *specifiers, NSBundle *bundle, NSString *table) {
	// Use the pane's table explicitly; never translate identifiers or actions.
	for(PSSpecifier* specifier in specifiers) {
		if(specifier.name.length) {
			specifier.name = [bundle localizedStringForKey:specifier.name value:specifier.name table:table];
		}
		NSString* footer = [specifier propertyForKey:@"footerText"];
		if(footer.length) {
			[specifier setProperty:[bundle localizedStringForKey:footer value:footer table:table] forKey:@"footerText"];
		}
	}
}

NSString *SHDWInstalledVersion(void) {
	// The status file is large; share the local result across both panes.
	static NSString* packageVersion;
	if(!packageVersion) {
		for(NSString* statusPath in @[
			JBPath(@"/var/lib/dpkg/status"),
			[@THEOS_PACKAGE_INSTALL_PREFIX stringByAppendingString:@"/var/lib/dpkg/status"]
		]) {
			if(![[NSFileManager defaultManager] fileExistsAtPath:statusPath]) continue;
			NSString* status = [NSString stringWithContentsOfFile:statusPath encoding:NSUTF8StringEncoding error:nil];
			if(status) {
				NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:@"(?:^|\\n)Package: me\\.jjolano\\.shadow\\n(?:[^\\n]+\\n)*?Version: ([^\\n]+)" options:0 error:nil];
				NSTextCheckingResult* match = [regex firstMatchInString:status options:0 range:NSMakeRange(0, status.length)];
				if(match) {
					packageVersion = [[status substringWithRange:[match rangeAtIndex:1]] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
					if(packageVersion.length) break;
					packageVersion = nil;
				}
			}
		}
	}
	return packageVersion;
}

BOOL SHDWAppEnabled(NSUserDefaults *prefs, NSString *appID) {
	NSDictionary* appPrefs = [prefs dictionaryForKey:appID];
	return SHDWApplicationEnabled(appPrefs,
		[prefs boolForKey:SHDWGlobalEnabledID],
		[prefs boolForKey:SHDWSingleToggleMigrationID], NO);
}

void SHDWWriteAppEnabled(NSUserDefaults *prefs, NSString *appID, BOOL enabled) {
	NSMutableDictionary* appPrefs = [[prefs dictionaryForKey:appID] mutableCopy] ?: [NSMutableDictionary new];
	appPrefs[SHDWAppEnabledID] = @(enabled);
	[appPrefs removeObjectForKey:SHDWAppDisabledID];
	[prefs setBool:YES forKey:SHDWSingleToggleMigrationID];
	[prefs setObject:[appPrefs copy] forKey:appID];
}

BOOL SHDWAppFollowsGlobal(NSUserDefaults *prefs, NSString *appID) {
	return !SHDWAppIsCustomized([prefs dictionaryForKey:appID]);
}

// Every plugin prefKey (Universal_*/Adapter_*), i.e. the per-app toggle surface.
static NSArray<NSString*>* SHDWHookTogglePrefKeys(void) {
	static NSArray<NSString*>* keys = nil;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		NSUInteger count = 0;
		const SHDWPlugin* plugins = SHDWPluginRegistry(&count);
		NSMutableArray<NSString*>* list = [NSMutableArray new];
		for(NSUInteger i = 0; i < count; i++) {
			if(plugins[i].prefKey) [list addObject:plugins[i].prefKey];
		}
		keys = [list copy];
	});
	return keys;
}

BOOL SHDWAppIsCustomized(id appPrefs) {
	if(![appPrefs isKindOfClass:[NSDictionary class]]) return NO;
	if([appPrefs objectForKey:SHDWAppEnabledID] != nil ||
	   [appPrefs objectForKey:SHDWAppDisabledID] != nil ||
	   [appPrefs objectForKey:SHDWDetectorAggressiveID] != nil) {
		return YES;
	}
	// A per-app hook toggle also makes the app customized (stops Follow Global).
	for(NSString* key in SHDWHookTogglePrefKeys()) {
		if([appPrefs objectForKey:key] != nil) return YES;
	}
	return NO;
}

BOOL SHDWResetApp(NSUserDefaults *prefs, NSString *appID) {
	if(appID.length == 0) return NO;
	[prefs removeObjectForKey:appID];
	// Do not roll back asynchronous defaults writes with a potentially stale snapshot.
	return [prefs synchronize];
}

UIImage *SHDWSettingsSymbol(NSString *name) {
	if(![UIImage respondsToSelector:@selector(systemImageNamed:)]) return nil;
	return [[UIImage systemImageNamed:name] imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}

void SHDWClearAppOverrides(NSUserDefaults *prefs, NSString *appID) {
	NSMutableDictionary* appPrefs = [[prefs dictionaryForKey:appID] mutableCopy];
	if(!appPrefs) {
		return;
	}
	[appPrefs removeObjectForKey:SHDWAppEnabledID];
	[appPrefs removeObjectForKey:SHDWAppDisabledID];
	[appPrefs removeObjectForKey:SHDWDetectorAggressiveID];
	[prefs setBool:YES forKey:SHDWSingleToggleMigrationID];
	// Drop the app's dictionary entirely once it holds no overrides, so a
	// "follow global" app leaves no residue in the backing plist.
	if(appPrefs.count == 0) {
		[prefs removeObjectForKey:appID];
	} else {
		[prefs setObject:[appPrefs copy] forKey:appID];
	}
}

BOOL SHDWAppAggressive(NSUserDefaults *prefs, NSString *appID) {
	NSDictionary* appPrefs = [prefs dictionaryForKey:appID];
	return SHDWDetectorAggressiveEnabled(appPrefs, [prefs boolForKey:SHDWDetectorAggressiveID]);
}

void SHDWWriteAppAggressive(NSUserDefaults *prefs, NSString *appID, BOOL aggressive) {
	NSMutableDictionary* appPrefs = [[prefs dictionaryForKey:appID] mutableCopy] ?: [NSMutableDictionary new];
	appPrefs[SHDWDetectorAggressiveID] = @(aggressive);
	[prefs setObject:[appPrefs copy] forKey:appID];
}

BOOL SHDWAppHookToggled(NSUserDefaults *prefs, NSString *appID, NSString *prefKey) {
	NSDictionary* appPrefs = [prefs dictionaryForKey:appID];
	id value = [appPrefs objectForKey:prefKey];
	if([value isKindOfClass:[NSNumber class]]) {
		return [value boolValue];
	}
	// Per-app unset: fall back to the global scalar of the same key, then the
	// built-in default. Mirrors Settings.m's merge order so the switch reflects
	// what the planner will actually apply.
	id global = [prefs objectForKey:prefKey];
	if([global isKindOfClass:[NSNumber class]]) {
		return [global boolValue];
	}
	id def = [SHDWDefaultHookSettings() objectForKey:prefKey];
	return def ? [def boolValue] : YES;
}

void SHDWWriteAppHookToggled(NSUserDefaults *prefs, NSString *appID, NSString *prefKey, BOOL enabled) {
	NSMutableDictionary* appPrefs = [[prefs dictionaryForKey:appID] mutableCopy] ?: [NSMutableDictionary new];
	appPrefs[prefKey] = @(enabled);
	[prefs setObject:[appPrefs copy] forKey:appID];
}

void SHDWToggleHaptic(void) {
	// Fresh instance per event: toggle flips are rare, allocation cost is
	// irrelevant next to the impact itself.
	UIImpactFeedbackGenerator* generator = [(UIImpactFeedbackGenerator*)[NSClassFromString(@"UIImpactFeedbackGenerator") alloc] initWithStyle:UIImpactFeedbackStyleLight];
	[generator impactOccurred];
}
