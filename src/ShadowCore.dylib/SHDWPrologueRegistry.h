#ifndef shdw_prologue_registry_h
#define shdw_prologue_registry_h

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <stdint.h>

// Original-prologue byte registry.
//
// ElleKit's inline lane overwrites the first bytes of a hooked function with a
// branch to the replacement. Tamper detectors (BShield et al.) recover the
// patch by reading the function's live bytes back out of the task with
// vm_read_overwrite() and comparing them to the expected prologue. To answer
// those reads with the pre-patch bytes, ShadowCore snapshots each function's
// prologue immediately before the inline patch is applied (in
// SHDWHookSession.hookFunction) and the vm_read_overwrite hook serves the
// snapshot for any range that overlaps a patched function.

// How many leading bytes of each hooked function to snapshot. arm64 inline
// patches are short (an adrp/ldr/br trampoline stub, <= 16 bytes); 32 bytes
// gives margin while staying small enough to store per function.
#define SHDW_PROLOGUE_SNAPSHOT_BYTES 32

// Record the current bytes at `function` as its pristine prologue. Called
// BEFORE the inline patch so the bytes captured are the stock ones. Safe to
// call for the same address twice (the first snapshot wins — re-hooks during
// repair/replay must not overwrite the pristine bytes with an already-patched
// view). No-op if the bytes cannot be read.
void SHDWPrologueRecord(const void* function);

// Overwrite `size` bytes starting at `address` in the caller's buffer with the
// snapshot of any patched function they overlap. Returns the number of bytes
// actually covered by snapshots (0 if the range touches no patched function).
// `buffer` is the destination the detector's vm_read_overwrite already filled
// with live bytes; this rewrites only the subranges that are patched, leaving
// the rest of the live read intact.
NSUInteger SHDWPrologueOverwrite(vm_address_t address, vm_size_t size, uint8_t* buffer);

#endif /* shdw_prologue_registry_h */
