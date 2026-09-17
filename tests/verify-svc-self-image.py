"""Exercise the actual raw-SVC add-image admission and initialization bodies."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ShadowCore.dylib/hooks/Universal/svc_patch.x"


def body(source: str, signature: str) -> str:
    start = source.index("{", source.index(signature))
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[source.index(signature):end]


source = SOURCE.read_text()
skip = body(source, "static BOOL shdw_svc_skip_image(")
header = body(source, "static void shdw_svc_patch_header(")
callback = body(source, "static void shdw_svc_image_add(")
deferred = body(source, "void shdw_svc_patch_deferred(void)")
install = body(source, "void shdw_svc_patch_install(void)")

# The app-bundle exemption remains a path-policy decision. Scanner identity is
# separate and must be decided before the callback looks an image up by path.
bundle_start = skip.index("if([imagePath isEqualToString:bundlePath]")
bundle_end = skip.index("// dyld reports", bundle_start)
assert "return NO;" in skip[bundle_start:bundle_end]

# Identity exclusion precedes any queue/patch work. The default add path
# queues (the drainer scans off the load path); the Universal_SvcSync gate is
# the only inline scan, and it returns before any queue work; the queue-full
# fallback still patches inline, only after the append attempt.
assert callback.index("if(!shdw_svc_own_image || mh == shdw_svc_own_image)") < callback.index(
    "pthread_mutex_lock(&shdw_svc_queue_lock)"
)
assert callback.index("atomic_load_explicit(&shdw_svc_sync_mode") < callback.index(
    "pthread_mutex_lock(&shdw_svc_queue_lock)"
)
fallback = callback[callback.index("if(!queued)"):]
assert "shdw_svc_patch_header(mh, slide)" in fallback

# The drain takes the queue lock and empties the queue before scanning.
assert deferred.index("pthread_mutex_lock(&shdw_svc_queue_lock)") < deferred.index(
    "shdw_svc_patch_header(pending[i]"
)
assert deferred.index("shdw_svc_queue_count = 0") < deferred.index("pthread_mutex_unlock")

assert install.index("dladdr((const void*)shdw_svc_patch_install, &info)") < install.index(
    "_dyld_register_func_for_add_image"
)

prefix = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* The add-image callback schedules its drain with libdispatch; the test
   drives the drain explicitly, so the debounce timer is swallowed whole
   (its block/function argument never reaches the compiler). */
#define dispatch_after(...) ((void)0)
#define dispatch_after_f(...) ((void)0)
#define dispatch_async(...) ((void)0)
#define dispatch_get_global_queue(...) ((void*)0)
#define QOS_CLASS_USER_INITIATED 0
#define RTLD_DEFAULT ((void*)0)
static void *dlsym(void *handle, const char *symbol) {
    (void)handle; (void)symbol; return NULL;
}

typedef int BOOL;
#define NO 0
#define YES 1

struct mach_header { int marker; };
typedef struct { const char *dli_fname; void *dli_fbase; } Dl_info;

#define SHDW_SVC_QUEUE_MAX 1024

static const struct mach_header *shdw_svc_own_image = NULL;
static _Atomic BOOL shdw_svc_sync_mode = NO;
static _Atomic BOOL shdw_svc_pools_enabled = NO;
static void (*shdw_svc_jit_wp)(int) = NULL;
void shdw_svc_patch_pools(void) { }
static void shdw_svc_pool_timer_start_once(void) { }
static pthread_mutex_t shdw_svc_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static const struct mach_header *shdw_svc_queue[SHDW_SVC_QUEUE_MAX];
static intptr_t shdw_svc_queue_slide[SHDW_SVC_QUEUE_MAX];
static size_t shdw_svc_queue_count = 0;
static _Atomic BOOL shdw_svc_drain_pending = NO;
static _Atomic uint64_t shdw_svc_drain_deadline = 0;

#define SHDW_SVC_DRAIN_QUIET_NS (400ull * 1000000ull)
#define SHDW_SVC_DRAIN_BATCH 64
/* clock_gettime_nsec_np is Apple-only; the test drives the drain explicitly,
   so the deadline value never matters here. */
#define clock_gettime_nsec_np(x) 0

static struct mach_header self_header, app_header, app_header2;
static const struct mach_header *images[2];
static const char *paths[2];
static uint32_t image_count;
static int image_count_calls, registrations, patches;
static const struct mach_header *replay_header, *last_patched;
static int dladdr_ok;
static const struct mach_header *dladdr_header;

static uint32_t _dyld_image_count(void) {
    image_count_calls++;
    return image_count;
}

static const struct mach_header *_dyld_get_image_header(uint32_t index) {
    return images[index];
}

static const char *_dyld_get_image_name(uint32_t index) {
    return paths[index];
}

static BOOL shdw_svc_skip_image(const char *path) {
    return !path || strncmp(path, "/bundle/", 8) != 0;
}

static void shdw_svc_patch_image(const struct mach_header *mh, intptr_t slide,
                                 const char *path) {
    (void)slide;
    (void)path;
    patches++;
    last_patched = mh;
}

static int dladdr(const void *address, Dl_info *info) {
    (void)address;
    if(!dladdr_ok) return 0;
    info->dli_fbase = (void *)dladdr_header;
    return 1;
}

static void shdw_svc_image_add(const struct mach_header *mh, intptr_t slide);
static void _dyld_register_func_for_add_image(
    void (*callback)(const struct mach_header *, intptr_t)) {
    registrations++;
    callback(replay_header, 0);
}

static void set_image(const struct mach_header *mh, const char *path) {
    image_count = 1;
    images[0] = mh;
    paths[0] = path;
}
'''

suffix = r'''
int main(void) {
    set_image(&self_header, "/bundle/ShadowCore.dylib");
    replay_header = &self_header;

    /* Resolve failure must not register a replay callback or scan anything. */
    dladdr_ok = 0;
    shdw_svc_patch_install();
    assert(registrations == 0);
    assert(image_count_calls == 0);
    assert(patches == 0);
    assert(shdw_svc_own_image == NULL);

    /* A resolved self header is excluded before image/path admission. */
    dladdr_ok = 1;
    dladdr_header = &self_header;
    shdw_svc_patch_install();
    assert(registrations == 1);
    assert(shdw_svc_own_image == &self_header);
    assert(image_count_calls == 0);
    assert(patches == 0);

    /* Defensive callback behavior is safe even if identity becomes unavailable. */
    shdw_svc_own_image = NULL;
    shdw_svc_image_add(&self_header, 0);
    assert(image_count_calls == 0);
    assert(patches == 0);

    /* A different image beneath the app bundle queues — no inline patch. */
    shdw_svc_own_image = &self_header;
    set_image(&app_header, "/bundle/Detector.dylib");
    shdw_svc_image_add(&app_header, 0);
    assert(patches == 0);
    assert(shdw_svc_queue_count == 1);
    assert(shdw_svc_drain_pending == YES);

    /* The drain scans queued images and empties the queue. */
    shdw_svc_patch_deferred();
    assert(patches == 1);
    assert(last_patched == &app_header);
    assert(shdw_svc_queue_count == 0);

    /* Images keep queueing after a drain; drain again scans them. */
    set_image(&app_header2, "/bundle/Late.framework/Late");
    shdw_svc_image_add(&app_header2, 0);
    assert(patches == 1);
    assert(shdw_svc_queue_count == 1);
    shdw_svc_patch_deferred();
    assert(patches == 2);
    assert(last_patched == &app_header2);

    /* An empty drain is a no-op. */
    shdw_svc_patch_deferred();
    assert(patches == 2);

    /* Universal_SvcSync: images scan inline on the add path, nothing queues. */
    shdw_svc_sync_mode = YES;
    set_image(&app_header, "/bundle/Sync.framework/Sync");
    shdw_svc_image_add(&app_header, 0);
    assert(patches == 3);
    assert(last_patched == &app_header);
    assert(shdw_svc_queue_count == 0);
    shdw_svc_sync_mode = NO;

    /* Queueing resumes once sync mode is off. */
    set_image(&app_header2, "/bundle/Async.framework/Async");
    shdw_svc_image_add(&app_header2, 0);
    assert(patches == 3);
    assert(shdw_svc_queue_count == 1);
    shdw_svc_patch_deferred();
    assert(patches == 4);

    puts("verify-svc-self-image: scanner admission assertions passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-svc-self-image-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    test.write_text(
        prefix + header + "\n\n" + callback + "\n\n" + deferred + "\n\n" + install + suffix
    )
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        str(test), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
