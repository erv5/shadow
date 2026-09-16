#import "SHDWRootListController.h"
#import "SHDWPrefs.h"

#import <Shadow/Core+Utilities.h>
#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@implementation SHDWRootListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
		SHDWLocalizeSpecifiers(_specifiers, [NSBundle bundleForClass:[self class]], @"Root");
		for(NSString* identifier in @[@"ApplicationsSummary", @"RootAbout"]) {
			UIImage* icon = SHDWSettingsSymbol([identifier isEqualToString:@"RootAbout"] ? @"info.circle" : @"square.grid.2x2");
			if(icon) [[self specifierForID:identifier] setProperty:icon forKey:@"iconImage"];
		}
	}

	return _specifiers;
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"Root"];
}

- (NSString *)rootVersionLine:(id)sender {
	// Root-pane identity: fork + installed version, visible without opening About.
	NSString* version = SHDWInstalledVersion();
	return version.length ? [version stringByAppendingString:@" (erv5 fork)"] : @"erv5 fork of jjolano/shadow";
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"ApplicationsSummary"]) {
		// Count apps not following the global settings: an app "follows
		// global" until it writes an explicit activation override (App_Enabled)
		// or a per-app aggressive override (Detector_Aggressive). Legacy
		// App_Disabled counts too, since it also overrides the global toggle.
		// The subtext is a bare number; with no overrides there is nothing to
		// display, so omit the label entirely.
		NSInteger customized = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if(SHDWAppIsCustomized(value)) {
				customized++;
			}
		}

		if(customized == 0) {
			return nil;
		}

		return [NSNumberFormatter localizedStringFromNumber:@(customized) numberStyle:NSNumberFormatterDecimalStyle];
	}

	return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	[prefs setObject:value forKey:[specifier identifier]];
	[prefs synchronize];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	// Re-read on return: the summary derives from switches changed on pushed
	// app pages, and the global switches can be wiped by Reset Settings in the
	// About pane. Without this, popping back shows stale switch/summary state
	// even though the stored values changed.
	for(NSString* specID in @[ @"Global_Enabled", @"Detector_Aggressive", @"ApplicationsSummary" ]) {
		PSSpecifier* specifier = [self specifierForID:specID];
		if(specifier) {
			[self reloadSpecifier:specifier];
		}
	}
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}

// --- Backup & Restore -------------------------------------------------------

- (NSString *)shdwPrefsPath {
	// me.jjolano.shadow.plist (resolves through the rootless jbroot symlink)
	return @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist";
}

- (NSString *)choicyPrefsPath {
	// Choicy's per-app tweak lists live in the same preferences dir.
	NSArray* candidates = @[
		@"/var/mobile/Library/Preferences/com.opa334.choicyprefs.plist",
		@"/var/jb/var/mobile/Library/Preferences/com.opa334.choicyprefs.plist",
	];
	for(NSString* path in candidates) {
		if([[NSFileManager defaultManager] fileExistsAtPath:path]) {
			return path;
		}
	}
	return candidates[0];
}

- (NSDictionary *)shdwExportBundle {
	NSMutableDictionary* bundle = [NSMutableDictionary new];
	bundle[@"format"] = @"shadow-backup";
	bundle[@"version"] = @(1);
	bundle[@"date"] = [[NSDate date] description];

	NSDictionary* shadow = [NSDictionary dictionaryWithContentsOfFile:[self shdwPrefsPath]];
	if(shadow) bundle[@"me.jjolano.shadow"] = shadow;

	NSDictionary* choicy = [NSDictionary dictionaryWithContentsOfFile:[self choicyPrefsPath]];
	if(choicy) bundle[@"com.opa334.choicyprefs"] = choicy;

	return bundle;
}

- (IBAction)exportConfig:(id)sender {
	NSDictionary* bundle = [self shdwExportBundle];
	NSString* outPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"shadow-config.plist"];
	if(![bundle writeToFile:outPath atomically:YES]) {
		[self shdwShowAlert:@"Export Failed" message:@"Could not write the backup file."];
		return;
	}

	UIActivityViewController* share = [[UIActivityViewController alloc]
		initWithActivityItems:@[[NSURL fileURLWithPath:outPath]] applicationActivities:nil];
	[self presentViewController:share animated:YES completion:nil];
}

- (IBAction)importConfig:(id)sender {
	UIDocumentPickerViewController* picker = [[UIDocumentPickerViewController alloc]
		initForOpeningContentTypes:@[[UTType typeWithIdentifier:@"public.plist"], [UTType typeWithIdentifier:@"public.data"]] asCopy:YES];
	picker.delegate = self;
	picker.allowsMultipleSelection = NO;
	[self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocuments:(NSArray<NSURL *> *)urls {
	NSURL* url = urls.firstObject;
	if(!url) return;

	BOOL secure = [url startAccessingSecurityScopedResource];
	NSDictionary* bundle = [NSDictionary dictionaryWithContentsOfFile:[url path]];
	if(secure) [url stopAccessingSecurityScopedResource];

	BOOL importedShadow = NO, importedChoicy = NO;

	if([bundle[@"me.jjolano.shadow"] isKindOfClass:[NSDictionary class]]) {
		importedShadow = [bundle[@"me.jjolano.shadow"] writeToFile:[self shdwPrefsPath] atomically:YES];
	}
	if([bundle[@"com.opa334.choicyprefs"] isKindOfClass:[NSDictionary class]]) {
		importedChoicy = [bundle[@"com.opa334.choicyprefs"] writeToFile:[self choicyPrefsPath] atomically:YES];
	}

	// Fallback: a bare me.jjolano.shadow.plist (no wrapper) imports as the Shadow config.
	if(!importedShadow && !importedChoicy && bundle && !bundle[@"format"]) {
		importedShadow = [bundle writeToFile:[self shdwPrefsPath] atomically:YES];
	}

	if(!importedShadow && !importedChoicy) {
		[self shdwShowAlert:@"Import Failed" message:@"That file is not a Shadow config backup."];
		return;
	}

	// Tell ChoicySB to reload (it reads its plist file directly); Shadow prefs
	// take effect on next app launch / respring.
	CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
		CFSTR("com.opa334.choicyprefs/ReloadPrefs"), NULL, NULL, YES);

	[self shdwShowAlert:@"Imported"
		message:@"Config restored. Respring for everything to take effect."];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
}

- (void)shdwShowAlert:(NSString *)title message:(NSString *)message {
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:title
		message:message preferredStyle:UIAlertControllerStyleAlert];
	[alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
	[self presentViewController:alert animated:YES completion:nil];
}
@end
