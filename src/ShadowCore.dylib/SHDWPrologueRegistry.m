#import "SHDWPrologueRegistry.h"

#import <string.h>
#import <os/lock.h>

typedef struct {
    vm_address_t address;                                  // patched function entry
    uint8_t      bytes[SHDW_PROLOGUE_SNAPSHOT_BYTES];      // pristine prologue
    BOOL         used;
} SHDWPrologueEntry;

// Bounded table: Shadow hooks a fixed, modest set of functions per process,
// plus every raw-svc site the svc patcher rewrites in app-bundled detector
// code (a BShield-class SDK alone carries ~100 such sites). 2048 covers both
// with headroom; each entry is 40 bytes.
#define SHDW_PROLOGUE_MAX 2048

static SHDWPrologueEntry gRegistry[SHDW_PROLOGUE_MAX];
static os_unfair_lock gLock = OS_UNFAIR_LOCK_INIT;

// Read the live bytes at `addr` into `out`. Uses a direct memcpy: at record
// time the page is present and readable (we are about to patch it), so a plain
// deref is safe and avoids a recursive vm_read_overwrite call into our own hook.
static BOOL shdw_read_live(const void* addr, uint8_t* out, NSUInteger len) {
    if(!addr) return NO;
    memcpy(out, addr, len);
    return YES;
}

void SHDWPrologueRecord(const void* function) {
    if(!function) return;
    vm_address_t addr = (vm_address_t)function;

    os_unfair_lock_lock(&gLock);
    // First snapshot wins: a repair/replay re-hook must not capture the
    // already-patched bytes over the pristine ones.
    for(NSUInteger i = 0; i < SHDW_PROLOGUE_MAX; i++) {
        if(gRegistry[i].used && gRegistry[i].address == addr) {
            os_unfair_lock_unlock(&gLock);
            return;
        }
    }
    for(NSUInteger i = 0; i < SHDW_PROLOGUE_MAX; i++) {
        if(!gRegistry[i].used) {
            uint8_t snap[SHDW_PROLOGUE_SNAPSHOT_BYTES];
            if(shdw_read_live(function, snap, sizeof(snap))) {
                gRegistry[i].address = addr;
                memcpy(gRegistry[i].bytes, snap, sizeof(snap));
                gRegistry[i].used = YES;
            }
            break;
        }
    }
    os_unfair_lock_unlock(&gLock);
}

NSUInteger SHDWPrologueOverwrite(vm_address_t address, vm_size_t size, uint8_t* buffer) {
    if(!buffer || size == 0) return 0;

    NSUInteger covered = 0;
    os_unfair_lock_lock(&gLock);
    for(NSUInteger i = 0; i < SHDW_PROLOGUE_MAX; i++) {
        if(!gRegistry[i].used) continue;

        vm_address_t fStart = gRegistry[i].address;
        vm_address_t fEnd   = fStart + SHDW_PROLOGUE_SNAPSHOT_BYTES;
        vm_address_t rStart = address;
        vm_address_t rEnd   = address + size;

        // Intersection of [rStart,rEnd) with the snapshot window [fStart,fEnd).
        vm_address_t oStart = rStart > fStart ? rStart : fStart;
        vm_address_t oEnd   = rEnd   < fEnd   ? rEnd   : fEnd;
        if(oStart >= oEnd) continue;

        // Copy the pristine bytes for the overlapping subrange into the right
        // offset of the caller's buffer.
        NSUInteger bufOff  = (NSUInteger)(oStart - rStart);
        NSUInteger snapOff = (NSUInteger)(oStart - fStart);
        NSUInteger len     = (NSUInteger)(oEnd - oStart);
        memcpy(buffer + bufOff, gRegistry[i].bytes + snapOff, len);
        covered += len;
    }
    os_unfair_lock_unlock(&gLock);
    return covered;
}
