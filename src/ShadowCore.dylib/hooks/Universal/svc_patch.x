#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Raw svc interception: inline `svc` syscalls never pass through libc
// wrappers, so the syscall(2)/__syscall(2) hooks in syscall.x cannot see
// them. This file scans loaded images' __TEXT for svc sites and redirects
// each site to a trampoline applying the same path policy as the syscall(2)
// dispatch. System images are never patched (re-entrancy); Shadow's own
// images are skipped too. Arm64 only: the !__arm64__ (armv7, rootful-legacy)
// lane is an intentionally empty stub — inline svc sites on 32-bit are NOT
// intercepted, only the syscall(2)/__syscall(2) rebind lane in syscall.x
// covers them. No functional change to hooking lanes here.
//
// A kernel-side sysent hook was considered (catch every svc, JIT or not)
// but is not implementable on modern iOS: sy_call must point at
// kernel-resident code, and arm64e's PPL forbids executing injected kernel
// memory — modern jailbreaks patch kernel data only.

#import "UniversalHooks.h"
#import "../../policy/PathPolicy.h"
#import "../../policy/ProcessPolicy.h"
#import "../../SHDWPrologueRegistry.h"
#import "path_rewrite.h"

#import <libkern/OSCacheControl.h>
#import <pthread.h>
#import <stdlib.h>
#import <sys/event.h>
#import <sys/syscall.h>
#import <fcntl.h>
#import <time.h>
#import <unistd.h>

#if defined(__arm64__)

// --- Natural-ENOENT rewrite (call-time path munging) ------------------------
// Prototype: for read-only path syscalls denied by the policy, rewrite the
// caller's path buffer in place (same length, middle of the final component
// → 0x01, see path_rewrite.c) and return "allow": the original svc then
// executes against the munged path and the kernel produces a REAL ENOENT.
// The rewritten buffer stays munged in the app's memory, so every later
// lookup of the same buffer — libc, NSFileManager, a helper process via
// argv — fails naturally, even through code Shadow does not hook. Falls back
// to the synthetic ENOENT when the buffer is not writable (e.g. a __TEXT
// string constant), the syscall is not in the rewrite set, or the
// Universal_PathRewrite is off. open-family with O_CREAT keeps the synthetic deny
// — the munged path would otherwise be CREATED as a side effect.
static BOOL shdw_svc_rewriteable(int sysno, uint64_t flags) {
    switch(sysno) {
        case SYS_access: case SYS_stat: case SYS_lstat:
        case SYS_stat64: case SYS_lstat64:
        case SYS_stat_extended: case SYS_lstat_extended:
        case SYS_stat64_extended: case SYS_lstat64_extended:
        case SYS_getattrlist: case SYS_getxattr: case SYS_listxattr:
        case SYS_readlink: case SYS_pathconf:
        case SYS_fstatat: case SYS_fstatat64:
        case SYS_execve:
            return YES;
        case SYS_open: case SYS_open_extended: case SYS_openat:
            return ((int)flags & O_CREAT) == 0;
        default:
            return NO;
    }
}

// --- Trampoline helper ------------------------------------------------------
// Runs with the app's registers saved on the stack (see the trampoline
// asm). A normal C function: may clobber x0-x18/lr freely, must preserve
// x19-x28 (the compiler does). Returns 0 = allow (execute the original
// svc), otherwise the errno the trampoline synthesizes with carry set
// (ENOENT for the path shapes, ESRCH for the kevent liveness shapes).
// Plain C linkage (Logos emits ObjC .m, no mangling), so the inline-asm
// `bl _shdw_svc_should_deny` resolves.
__attribute__((used, noinline)) int shdw_svc_should_deny(uint64_t sysno, uint64_t a0, uint64_t a1, uint64_t a2, uintptr_t caller_lr) {
    // The patched site is in app/detector code by construction (system and
    // Shadow images are never scanned), but keep the same caller gate the
    // libc hooks use — the return address is passed explicitly because
    // isCallerExternal()'s builtin read would see the trampoline's own
    // (ShadowCore) address.
    if(!shdw_caller_is_external((const void*)caller_lr)) {
        return 0;
    }

    // Indirect-syscall site: svc with x16=0 (SYS_syscall) carries the real
    // number in the first argument register and every argument shifts one
    // register. BShield hides a probe's number this way. Re-dispatch on the
    // real number; the trampoline only captured through a2, so an indirect
    // kevent (which needs a3) fails open rather than misreads a register.
    if((int)sysno == SYS_syscall) {
        int real = (int)a0;
        if(real == SYS_syscall || real < 0) {
            return 0;
        }
        return shdw_svc_should_deny((uint64_t)real, a1, a2, 0, caller_lr);
    }

    shdw_raw_syscall_category_t cat = shdw_raw_syscall_category((int)sysno);

    if(cat == SHADW_RAW_CAT_PATH) {
        const char* path = (const char*)a0;

        if(!path || !path[0]) {
            return 0;
        }

        // Same behavioral tripwire as the libc hooks (SHADOW_TRIP): touching
        // a JB-indicator path via raw svc is detector evidence — escalate.
        if(shdw_is_jb_probe(path)) {
            shdw_detector_detected("svc");
        }

        // Same predicate PAIR as the libc/syscall(2) path hooks: the ruleset
        // AND the external-hidden set. A raw svc lookup must not expose an
        // object the wrappers report absent.
        BOOL hidden = shdw_path_is_external_hidden(path);

        if(!hidden && ![_shadow isCPathRestricted:path]) {
            return 0;
        }

        // External-hidden objects always answer synthetic ENOENT (the
        // path-rewrite munge would let the real svc resolve the still-present
        // file). Only the ruleset case takes the natural-ENOENT rewrite.
        if(hidden) {
            return ENOENT;
        }

        // Natural-ENOENT rewrite: munge the buffer and let the real svc run.
        size_t moff = shdw_path_munge_offset(path);

        if(shdw_path_rewrite_enabled()
           && shdw_svc_rewriteable((int)sysno, a1)
           && moff != (size_t)-1
           && shdw_path_buf_writable(path + moff)
           && shdw_path_munge_path((char*)path)) {
            return 0;
        }

        return ENOENT;
    }

    if(cat == SHADW_RAW_CAT_AT) {
        const char* path = (const char*)a1;

        if(!path || !path[0]) {
            return 0;
        }

        if(shdw_is_jb_probe(path)) {
            shdw_detector_detected("svc");
        }

        // Same dirfd-aware policy as the syscall(2) dispatch (sets errno on
        // denial; the trampoline ignores errno and synthesizes the raw
        // return instead).
        if(!shdw_at_path_denied((int)a0, path)) {
            return 0;
        }

        // Natural-ENOENT rewrite (openat flags live in a2, now passed by the
        // trampoline; fstatat/fstatat64 are read-only and safe).
        size_t moff = shdw_path_munge_offset(path);

        if(shdw_path_is_absolute(path)
           && shdw_path_rewrite_enabled()
           && shdw_svc_rewriteable((int)sysno, a2)
           && moff != (size_t)-1
           && shdw_path_buf_writable(path + moff)
           && shdw_path_munge_path((char*)path)) {
            return 0;
        }

        return ENOENT;
    }

#ifdef SYS_freadlink
    if(cat == SHADW_RAW_CAT_FREADLINK) {
        // Raw freadlink(fd): same fd policy as the syscall(2) dispatch —
        // fresh F_GETPATH, fail open when the fd has no nameable path. The
        // trampoline ignores errno and synthesizes the raw return.
        if(shdw_fd_path_restricted((int)a0)) {
            return ENOENT;
        }
        return 0;
    }
#endif

    if(cat == SHADW_RAW_CAT_KEVENT || cat == SHADW_RAW_CAT_KEVENT64) {
        // Inline-svc kevent(363)/kevent64(369): same EVFILT_PROC-only ESRCH
        // as the libc + syscall(2) hooks. The trampoline carries only
        // (sysno, a0=kq, a1=changelist, a2=nchanges) — sufficient, the policy
        // keys on the changelist head. The 64-bit changelist is scanned with
        // its own type (struct kevent64_s layout verified against the SDK
        // sys/event.h: ident u64 @0, filter s16 @8 — 48-byte elements), never
        // as struct kevent. Self-pid and non-PROC filters pass through;
        // unclassifiable pids fail open. The trampoline synthesizes the
        // returned ESRCH with carry set (stock-dead shape).
        const void* changelist = (const void*)a1;
        long nchanges = (long)a2;

        if(changelist && nchanges > 0) {
            pid_t self = getpid();

            for(long i = 0; i < nchanges; i++) {
                int16_t filter;
                uint64_t ident;

                if(cat == SHADW_RAW_CAT_KEVENT64) {
                    const struct kevent64_s* chl = (const struct kevent64_s*)changelist;
                    filter = chl[i].filter;
                    ident = chl[i].ident;
                } else {
                    const struct kevent* chl = (const struct kevent*)changelist;
                    filter = chl[i].filter;
                    ident = (uint64_t)chl[i].ident;
                }

                if(filter == EVFILT_PROC) {
                    pid_t pid = (pid_t)ident;

                    if(pid > 0 && pid != self && shdw_pid_is_restricted(pid)) {
                        return ESRCH;
                    }
                }
            }
        }

        return 0;
    }

    return 0;
}

// --- Naked trampolines ------------------------------------------------------
// XNU ignores svc's immediate, so one canonical trampoline handles every
// encoding. Save all caller-saved registers + x16 (syscall
// number) + lr, ask the helper, then either synthesize the errno return
// (x0 = helper's errno, carry set — Darwin's kernel error convention) or
// restore and execute the original svc.
#define SHADW_SVC_TRAMPOLINE(NAME, IMM) \
__attribute__((naked, used, noinline)) static void NAME(void) { \
    __asm__ volatile( \
        "stp x0, x1, [sp, #-16]!\n" \
        "stp x2, x3, [sp, #-16]!\n" \
        "stp x4, x5, [sp, #-16]!\n" \
        "stp x6, x7, [sp, #-16]!\n" \
        "stp x8, x9, [sp, #-16]!\n" \
        "stp x10, x11, [sp, #-16]!\n" \
        "stp x12, x13, [sp, #-16]!\n" \
        "stp x14, x15, [sp, #-16]!\n" \
        "stp x16, x17, [sp, #-16]!\n" \
        "stp x18, lr, [sp, #-16]!\n" \
        /* x0 = sysno (x16), x1 = a0, x2 = a1, x3 = a2, x4 = caller lr */ \
        "mov x2, x1\n" \
        "mov x1, x0\n" \
        "mov x0, x16\n" \
        /* Ten 16-byte pushes above (x0/x1 .. x18/lr): the saved x2 slot is */ \
        /* at sp+128 (saved x3 is at sp+136). a2 must be the third syscall */ \
        /* argument (openat flags, kevent nchanges), not x3. */ \
        "ldr x3, [sp, #128]\n" \
        "ldr x4, [sp, #8]\n" \
        "bl _shdw_svc_should_deny\n" \
        "cbz x0, 1f\n" \
        /* deny: x0 already holds the errno to synthesize (ENOENT for the */ \
        /* path shapes, ESRCH for kevent) — set carry (Darwin's kernel */ \
        /* error convention) and return, keeping x0 */ \
        "mov x1, #0x20000000\n" \
        "msr nzcv, x1\n" \
        "ldp x18, lr, [sp], #16\n" \
        "ldp x16, x17, [sp], #16\n" \
        "ldp x14, x15, [sp], #16\n" \
        "ldp x12, x13, [sp], #16\n" \
        "ldp x10, x11, [sp], #16\n" \
        "ldp x8, x9, [sp], #16\n" \
        "ldp x6, x7, [sp], #16\n" \
        "ldp x4, x5, [sp], #16\n" \
        "ldp x2, x3, [sp], #16\n" \
        "ldr x1, [sp, #8]\n" \
        "add sp, sp, #16\n" \
        "ret\n" \
        "1:\n" \
        /* allow: restore everything, execute the original svc */ \
        "ldp x18, lr, [sp], #16\n" \
        "ldp x16, x17, [sp], #16\n" \
        "ldp x14, x15, [sp], #16\n" \
        "ldp x12, x13, [sp], #16\n" \
        "ldp x10, x11, [sp], #16\n" \
        "ldp x8, x9, [sp], #16\n" \
        "ldp x6, x7, [sp], #16\n" \
        "ldp x4, x5, [sp], #16\n" \
        "ldp x2, x3, [sp], #16\n" \
        "ldp x0, x1, [sp], #16\n" \
        "svc #" IMM "\n" \
        "ret\n" \
    ); \
}

SHADW_SVC_TRAMPOLINE(shdw_svc_trampoline_80, "0x80")

// --- Scanner ----------------------------------------------------------------

#define SHDW_SVC_OPCODE_MASK 0xFFE0001FU
#define SHDW_SVC_OPCODE      0xD4000001U

static inline BOOL shdw_svc_is_instruction(uint32_t insn) {
    return (insn & SHDW_SVC_OPCODE_MASK) == SHDW_SVC_OPCODE;
}

// Constant-x16 recovery for one svc site: scans back at most 6 instructions
// for the movz w16/x16,#imm that establishes the syscall number (the
// compiler idiom for a constant-sysno wrapper: mov plastered just above the
// svc, verified across the harness + detector images). Returns the number,
// or -1 when x16 is dynamic (mov x16,xN, ldr, movk-first, ...) or not found
// within the window. Reads only inside [words, words+nwords).
static long shdw_svc_site_const_sysno(const uint32_t* words, size_t nwords, size_t w) {
    for(int back = 1; back <= 6; back++) {
        if((size_t)back > w) {
            return -1;
        }

        uint32_t insn = words[w - back];

        // movz w16,#imm16 / movz x16,#imm16 (any hw shift): the value is the
        // full shifted immediate — a shifted 26 stays 26 only when the
        // upper chunks are zero, which the shift math below captures.
        if((insn & 0xFFE0001F) == 0x52800010 || (insn & 0xFFE0001F) == 0xD2800010) {
            uint32_t hw = (insn >> 21) & 0x3;
            uint64_t val = (uint64_t)((insn >> 5) & 0xFFFF) << (hw * 16);
            return (long)val;
        }

        // movk w16/x16 first: the low chunk came from elsewhere (or a movz
        // outside the window) — value unknown at patch time.
        if((insn & 0xFFE0001F) == 0x72800010 || (insn & 0xFFE0001F) == 0xF2800010) {
            return -1;
        }
    }

    return -1;
}

// Images that must never be patched (see the file header: recursion safety
// and trampoline self-protection).
static BOOL shdw_svc_skip_image(const char* path) {
    if(!path || !path[0]) {
        return YES;
    }

    if(strncmp(path, "/System/", 8) == 0) {
        return YES;
    }

    if(strncmp(path, "/usr/", 5) == 0) {
        return YES;
    }

    NSString* imagePath = [NSString stringWithUTF8String:path];
    NSString* bundlePath = [NSBundle mainBundle].bundlePath;
    if([imagePath isEqualToString:bundlePath] ||
       [imagePath hasPrefix:[bundlePath stringByAppendingString:@"/"]]) {
        return NO;
    }

    // dyld reports the canonical preboot path for rootless apps while
    // NSBundle can retain /var/jb. Code inside procursus/Applications is
    // still app-owned detector code, not a bootstrap library.
    if(strstr(path, "/procursus/Applications/") != NULL) {
        return NO;
    }

    // Rootless jailbreak root: /var/jb resolves to
    // /private/preboot/<uuid>/procursus. The jailbreak's own dylibs
    // (systemhook, HKGum, libroot, ...) are NOT detector code — patching
    // their svc sites corrupts them and crashes the process.
    if(strstr(path, "/procursus/") != NULL) {
        return YES;
    }

    if(shdw_is_shadow_runtime_image(path)) {
        return YES;
    }

    return NO;
}

// Redirects one image svc site to the canonical trampoline. Idempotent: a
// patched site is a bl instruction, so a re-scan never matches it.
static _Atomic BOOL shdw_svc_far_site_seen = NO;

static void shdw_svc_try_patch_site(uintptr_t site, uint32_t insn, const char* where) {
    (void)where;
    uintptr_t target = 0;

    if(!shdw_svc_is_instruction(insn)) return;
    target = (uintptr_t)shdw_svc_trampoline_80;

    // A64 B/BL immediates are relative to the branch instruction's address.
    int64_t delta = (int64_t)target - (int64_t)site;

    if(delta < -0x8000000LL || delta > 0x7FFFFFCLL) {
        // Logging while every other thread is stopped can deadlock on a
        // runtime lock held by one of those threads. The caller reports this
        // once after the stop-the-world window instead.
        atomic_store_explicit(&shdw_svc_far_site_seen, YES, memory_order_relaxed);
        return;
    }

    // A detector reading its own __TEXT back (BShield's vm_read_overwrite
    // self-scan) would see the branch where its svc word was. Record the
    // pristine bytes first so the registry replays them on such reads —
    // the same cover the HookKit inline sites already get.
    SHDWPrologueRecord((const void*)site);

    *(uint32_t*)site = 0x94000000 | ((uint32_t)(delta >> 2) & 0x3FFFFFF);
    sys_icache_invalidate((void*)site, 4);
}

// All image callbacks converge here. The recursive lock handles an unusual
// same-thread callback without deadlocking; nested stop/resume pairs preserve
// the outer suspension counts.
static pthread_mutex_t shdw_svc_patch_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER;

static void shdw_svc_dispose_thread_list(thread_act_array_t threads,
                                         mach_msg_type_number_t count,
                                         mach_port_t current) {
    for(mach_msg_type_number_t i = 0; i < count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  (vm_size_t)count * sizeof(thread_t));

    if(current != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), current);
    }
}

static void shdw_svc_dispose_object(mach_port_t* object_name) {
    if(object_name && *object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), *object_name);
        *object_name = MACH_PORT_NULL;
    }
}

// Suspend exactly the threads whose thread_suspend call succeeded. This
// avoids accidentally decrementing a pre-existing suspend count if a thread
// exits between task_threads() and the loop.
static BOOL shdw_svc_suspend_others(thread_act_array_t* threads_out,
                                    mach_msg_type_number_t* count_out,
                                    mach_port_t* current_out) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    mach_port_t current = mach_thread_self();

    if(current == MACH_PORT_NULL) {
        return NO;
    }

    kern_return_t kr = task_threads(mach_task_self(), &threads, &count);

    if(kr != KERN_SUCCESS || !threads) {
        if(threads) {
            shdw_svc_dispose_thread_list(threads, count, current);
        } else {
            mach_port_deallocate(mach_task_self(), current);
        }

        return NO;
    }

    mach_msg_type_number_t suspended_through = 0;

    for(; suspended_through < count; suspended_through++) {
        if(threads[suspended_through] == current) {
            continue;
        }

        if(thread_suspend(threads[suspended_through]) != KERN_SUCCESS) {
            for(mach_msg_type_number_t i = 0; i < suspended_through; i++) {
                if(threads[i] != current) {
                    thread_resume(threads[i]);
                }
            }

            shdw_svc_dispose_thread_list(threads, count, current);
            return NO;
        }
    }

    *threads_out = threads;
    *count_out = count;
    *current_out = current;
    return YES;
}

static void shdw_svc_resume_others(thread_act_array_t threads,
                                   mach_msg_type_number_t count,
                                   mach_port_t current) {
    for(mach_msg_type_number_t i = 0; i < count; i++) {
        if(threads[i] != current) {
            thread_resume(threads[i]);
        }
    }
}

// Patch one executable range. The word-wise scan runs unlocked while other
// threads run, collecting candidate sites; the stop-the-world window then
// covers only vm_protect + a per-site re-verify/patch, so its cost tracks the
// number of svc sites rather than the segment size (a deferred 100MB+ main
// executable freezes a running app for milliseconds, not for the scan).
// __TEXT changes only through this function (under its lock), so preflight
// offsets stay valid; each is still re-read under suspension in case a racing
// scanner patched it. The scan window [scan_addr, +scan_size) is the exact
// instruction-bearing section; the protect window is its page-aligned cover
// (vm_protect needs page alignment; a section can start mid-page).
static void shdw_svc_patch_memory(uintptr_t scan_addr, size_t scan_size,
                                  uintptr_t protect_addr, size_t protect_size,
                                  vm_prot_t original_prot, const char* where) {
    if(scan_size < 4 || scan_addr > UINTPTR_MAX - scan_size) {
        return;
    }

    const uint32_t* words = (const uint32_t*)scan_addr;
    size_t nwords = scan_size / 4;

    size_t* sites = NULL;
    size_t nsites = 0, capacity = 0;

    for(size_t w = 0; w < nwords; w++) {
        if(shdw_svc_is_instruction(words[w])) {
            if(nsites == capacity) {
                size_t grown = capacity ? capacity * 2 : 64;
                size_t* resized = realloc(sites, grown * sizeof(*sites));

                if(!resized) {
                    free(sites);
                    return;  // fail-soft: leave this range for a later pass
                }

                sites = resized;
                capacity = grown;
            }

            sites[nsites++] = w;
        }
    }

    if(!nsites) {
        free(sites);
        return;
    }

    pthread_mutex_lock(&shdw_svc_patch_lock);

    // Another scanner may have patched sites while this caller waited; drop
    // the dead ones (a patched site reads as a bl, never an svc).
    size_t live = 0;

    for(size_t s = 0; s < nsites; s++) {
        if(shdw_svc_is_instruction(words[sites[s]])) {
            sites[live++] = sites[s];
        }
    }

    if(!live) {
        pthread_mutex_unlock(&shdw_svc_patch_lock);
        free(sites);
        return;
    }

    nsites = live;

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    mach_port_t current = MACH_PORT_NULL;

    if(!shdw_svc_suspend_others(&threads, &thread_count, &current)) {
        pthread_mutex_unlock(&shdw_svc_patch_lock);
        free(sites);
        return;
    }

    vm_prot_t restore_prot = original_prot;
    vm_region_basic_info_data_64_t current_info;
    mach_msg_type_number_t current_info_count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_address_t current_region = protect_addr;
    vm_size_t current_region_size = 0;
    mach_port_t current_object = MACH_PORT_NULL;

    kern_return_t current_kr = vm_region_64(mach_task_self(), &current_region,
                                            &current_region_size,
                                            VM_REGION_BASIC_INFO_64,
                                            (vm_region_info_t)&current_info,
                                            &current_info_count, &current_object);

    if(current_object != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), current_object);
    }

    if(current_kr == KERN_SUCCESS) {
        if(!(current_info.protection & VM_PROT_EXECUTE)) {
            shdw_svc_resume_others(threads, thread_count, current);
            shdw_svc_dispose_thread_list(threads, thread_count, current);
            pthread_mutex_unlock(&shdw_svc_patch_lock);
            free(sites);
            return;
        }

        // Re-read protection after stopping the world so a racing mprotect
        // cannot be undone by restoring stale preflight state.
        restore_prot = current_info.protection;
    }

    // Code-signed __TEXT's max_protection is r-x, so a plain vm_protect
    // READ|WRITE is denied (KERN_PROTECTION_FAILURE) — the same wall dyld.x's
    // load-command rewrite hits. Request VM_PROT_COPY, which forces a private
    // copy-on-write mapping and raises max_protection to include WRITE; only
    // the written site pages materialize, the rest stay shared. Falls back
    // to plain RW on kernels that reject COPY here; fail-soft either way.
    BOOL protected_for_write = vm_protect(mach_task_self(), protect_addr, protect_size,
                                          FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS;

    if(!protected_for_write) {
        protected_for_write = vm_protect(mach_task_self(), protect_addr, protect_size,
                                         FALSE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS;
    }

    BOOL restore_failed = NO;

    if(protected_for_write) {
        uint32_t* writable = (uint32_t*)scan_addr;

        for(size_t s = 0; s < nsites; s++) {
            size_t w = sites[s];
            uint32_t insn = writable[w];

            if(!shdw_svc_is_instruction(insn)) {
                continue;
            }

            // Never redirect a constant-x16 ptrace site. The svc helper
            // can only allow a ptrace call or synthesize an errno — it
            // cannot neutralize PT_DENY_ATTACH the way the syscall(2)
            // dispatch does — and redirecting an early anti-debug
            // initializer's deny_attach through the trampoline hangs
            // process init (measured iPhone7/iOS 15.8.3: init stalls
            // with the main binary's deny_attach site redirected,
            // completes with it left alone). Leaving the site also
            // matches every prior build's behavior (the helper never
            // policed PTRACE). Register-x16 sites always patch: their
            // number is unknowable statically and the kevent probe path
            // is one of them.
            if(shdw_svc_site_const_sysno(writable, nwords, w) == SYS_ptrace) {
                continue;
            }

            shdw_svc_try_patch_site(scan_addr + w * 4, insn, where);
        }

        // Restore execute permission before any other thread can run again.
        if(vm_protect(mach_task_self(), protect_addr, protect_size, FALSE, restore_prot) != KERN_SUCCESS) {
            restore_failed = YES;
            // Keep a failed exact restore from leaving an executable page
            // permanently non-executable. The fallback intentionally favors
            // liveness over preserving an unusual extra protection bit.
            vm_protect(mach_task_self(), protect_addr, protect_size, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
        }
    }

    shdw_svc_resume_others(threads, thread_count, current);
    shdw_svc_dispose_thread_list(threads, thread_count, current);
    pthread_mutex_unlock(&shdw_svc_patch_lock);
    free(sites);

    if(restore_failed) {
        NSLog(@"[Shadow][svc] protection restore failed in %s (fallback RX)", where);
    }

    if(atomic_exchange_explicit(&shdw_svc_far_site_seen, NO, memory_order_relaxed)) {
        NSLog(@"[Shadow][svc] svc site skipped in %s", where);
    }
}

// Scans one image's instruction-bearing sections for svc sites and redirects
// them to the matching trampoline. Only sections flagged as instruction
// sections are scanned: __TEXT also carries pure-data sections (__const,
// metadata), and a data word matching the svc encoding is inert — patching it
// corrupts whatever it actually is (observed on-device: an embedded LZMA blob
// in a payment SDK's __const got three words rewritten and the app SIGSEGV'd
// decompressing it). vm_protect fail-soft dance mirrors dyld.x's
// memory-hiding patch. Idempotent: patched sites are bl instructions, so a
// re-scan never matches them.
static void shdw_svc_patch_image(const struct mach_header* mh, intptr_t slide, const char* path) {
    if(mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64) {
        return;
    }

    const struct load_command* lc = (const struct load_command*)((const char*)mh + sizeof(struct mach_header_64));

    for(uint32_t i = 0; i < mh->ncmds; i++) {
        if(lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;

            if(strcmp(seg->segname, "__TEXT") == 0) {
                const struct section_64* sect = (const struct section_64*)(seg + 1);

                for(uint32_t s = 0; s < seg->nsects; s++, sect++) {
                    if(!(sect->flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))
                       || sect->size < 4) {
                        continue;
                    }

                    uintptr_t saddr = (uintptr_t)sect->addr + (uintptr_t)slide;
                    size_t ssize = (size_t)sect->size;

                    // vm_protect needs page-aligned bounds; a section can
                    // start mid-page. Cover it, scan only the section bytes.
                    uintptr_t paddr = saddr & ~(uintptr_t)(vm_page_size - 1);
                    size_t psize = (size_t)(((saddr + ssize + vm_page_size - 1)
                                             & ~(uintptr_t)(vm_page_size - 1)) - paddr);

                    vm_region_basic_info_data_64_t info;
                    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
                    vm_address_t region = saddr;
                    vm_size_t region_size = 0;
                    mach_port_t object_name = MACH_PORT_NULL;
                    vm_prot_t original_prot = VM_PROT_READ | VM_PROT_EXECUTE;

                    kern_return_t region_kr = vm_region_64(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object_name);
                    shdw_svc_dispose_object(&object_name);

                    if(region_kr == KERN_SUCCESS) {
                        original_prot = info.protection;
                    }

                    shdw_svc_patch_memory(saddr, ssize, paddr, psize, original_prot, path);
                }

                return;
            }
        }

        lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
    }
}

// Add-image callback: resolve the image path (the callback only carries the
// header), apply the skip rule, scan. Registered through the REAL dyld
// registration (the dyld.x hook passes Shadow-internal callers through), so
// the registration replay covers every already-loaded image before the app
// runs.
//
// Async scan queue: this callback runs inside dyld's load path, so scanning
// inline would tax every dlopen the app makes — image-heavy apps load
// hundreds of frameworks at startup, each serialized behind its scan, all
// under dyld's lock. Images are recorded here and scanned by a utility-queue
// drainer off the load path (trailing 400ms debounce: a burst coalesces into
// one drain when it goes quiet rather than a stop-the-world patch every few
// hundred ms mid-storm). Detector escalation (HookCoordinator calls
// shdw_svc_patch_deferred) forces an immediate synchronous drain so a detected
// detector never waits on the queue. A full queue falls back to scanning
// inline so coverage is never dropped for capacity.
#define SHDW_SVC_QUEUE_MAX 1024

static const struct mach_header* shdw_svc_own_image = NULL;

static pthread_mutex_t shdw_svc_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static const struct mach_header* shdw_svc_queue[SHDW_SVC_QUEUE_MAX];
static intptr_t shdw_svc_queue_slide[SHDW_SVC_QUEUE_MAX];
static size_t shdw_svc_queue_count = 0;
static _Atomic BOOL shdw_svc_drain_pending = NO;
static _Atomic uint64_t shdw_svc_drain_deadline = 0;   // monotonic ns, trailing debounce

#define SHDW_SVC_DRAIN_QUIET_NS (50ull * NSEC_PER_MSEC)
// Batch cap: drain immediately once this many images wait. A long launch storm
// (continuous dlopens for tens of seconds) otherwise starves the trailing
// debounce — its quiet window never opens, detector svc sites sit unpatched,
// and a raw-svc probe during the storm sees the real filesystem (detection).
#define SHDW_SVC_DRAIN_BATCH 64

static void shdw_svc_patch_header(const struct mach_header* mh, intptr_t slide) {
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        if(_dyld_get_image_header(i) == mh) {
            const char* path = _dyld_get_image_name(i);

            if(path && path[0] && !shdw_svc_skip_image(path)) {
                shdw_svc_patch_image(mh, slide, path);
            }

            return;
        }
    }
}

// Scans every queued image now. Debounce-scheduled on a utility queue after
// records; called synchronously by the detector-escalation path.
void shdw_svc_patch_deferred(void) {
    const struct mach_header* pending[SHDW_SVC_QUEUE_MAX];
    intptr_t pending_slide[SHDW_SVC_QUEUE_MAX];

    pthread_mutex_lock(&shdw_svc_queue_lock);
    size_t pending_count = shdw_svc_queue_count;
    if(pending_count) {
        memcpy(pending, shdw_svc_queue, pending_count * sizeof(*pending));
        memcpy(pending_slide, shdw_svc_queue_slide, pending_count * sizeof(*pending_slide));
        shdw_svc_queue_count = 0;
    }
    pthread_mutex_unlock(&shdw_svc_queue_lock);

    for(size_t i = 0; i < pending_count; i++) {
        shdw_svc_patch_header(pending[i], pending_slide[i]);
    }
}

// Drainer for the trailing debounce (C-function form — dispatch_after_f needs
// no blocks, so no ARC capture games): re-arms while records keep arriving,
// drains once the queue has been quiet for SHDW_SVC_DRAIN_QUIET_NS.
static void shdw_svc_drain_async(void* unused) {
    (void)unused;

    uint64_t dl = atomic_load_explicit(&shdw_svc_drain_deadline, memory_order_acquire);
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC);

    if(now < dl) {
        dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(dl - now)),
                         dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), NULL, shdw_svc_drain_async);
        return;
    }

    atomic_store_explicit(&shdw_svc_drain_pending, NO, memory_order_release);
    shdw_svc_patch_deferred();
}

static void shdw_svc_image_add(const struct mach_header* mh, intptr_t slide) {
    if(!shdw_svc_own_image || mh == shdw_svc_own_image) {
        return;
    }

    BOOL queued = NO;

    pthread_mutex_lock(&shdw_svc_queue_lock);

    if(shdw_svc_queue_count < SHDW_SVC_QUEUE_MAX) {
        shdw_svc_queue[shdw_svc_queue_count] = mh;
        shdw_svc_queue_slide[shdw_svc_queue_count] = slide;
        shdw_svc_queue_count++;
        queued = YES;
    }

    pthread_mutex_unlock(&shdw_svc_queue_lock);

    if(!queued) {
        shdw_svc_patch_header(mh, slide);
        return;
    }

    // Trailing debounce: each record pushes the deadline out, so an image-load
    // burst (hundreds of dlopens at app startup) coalesces into one drain after
    // it goes quiet instead of a stop-the-world patch every few ms mid-storm.
    atomic_store_explicit(&shdw_svc_drain_deadline,
        clock_gettime_nsec_np(CLOCK_MONOTONIC) + SHDW_SVC_DRAIN_QUIET_NS,
        memory_order_release);

    // Batch cap fires immediately: during a continuous dlopen storm the
    // trailing window never opens, so cap how long svc sites can sit unpatched.
    if(shdw_svc_queue_count >= SHDW_SVC_DRAIN_BATCH) {
        atomic_store_explicit(&shdw_svc_drain_deadline, 0, memory_order_release);
        if(!atomic_exchange_explicit(&shdw_svc_drain_pending, YES, memory_order_acq_rel)) {
            dispatch_after_f(DISPATCH_TIME_NOW,
                             dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), NULL, shdw_svc_drain_async);
        }
        return;
    }

    if(!atomic_exchange_explicit(&shdw_svc_drain_pending, YES, memory_order_acq_rel)) {
        dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW, (int64_t)SHDW_SVC_DRAIN_QUIET_NS),
                         dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), NULL, shdw_svc_drain_async);
    }
}

// Installed from the universal syscall installer, so its preference gates it (the
// unit only installs when the pref is on). Idempotent.
void shdw_svc_patch_install(void) {
    static BOOL installed = NO;

    if(installed) {
        return;
    }

    Dl_info info = {0};
    if(!dladdr((const void*)shdw_svc_patch_install, &info) || !info.dli_fbase) {
        return;
    }

    shdw_svc_own_image = (const struct mach_header*)info.dli_fbase;
    installed = YES;
    _dyld_register_func_for_add_image(shdw_svc_image_add);

    // The registration replay queued every already-loaded image; patch them
    // now, synchronously, before returning. The app's linked frameworks were
    // all mapped before Shadow's initializer ran, so this one drain leaves no
    // window where a detector constructor can observe its own svc sites
    // unpatched: the trailing debounce only goes quiet 50ms after the last
    // record, but dyld starts running initializers immediately after the last
    // map, and a BShield-class consistency probe in a constructor verdicts on
    // the spot (observed: MyViettel error 3 with the async-only path).
    shdw_svc_patch_deferred();
}

#else   // !__arm64__

// Rootful-legacy armv7 lane: no ARM64 svc interception (arm64-only
// encoding scan; see the file header). The stub keeps syscall.x linkable.
void shdw_svc_patch_install(void) {
}

void shdw_svc_patch_deferred(void) {
}

#endif  // __arm64__
