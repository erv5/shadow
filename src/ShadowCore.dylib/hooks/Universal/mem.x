#import "UniversalHooks.h"

#import "../../SHDWPrologueRegistry.h"

#ifndef VM_MAP_READ_NULL
typedef vm_map_t vm_map_read_t;
#endif

// vm_region policy: a returned region whose start address lies inside a
// restricted image interval is SKIPPED — the original is re-called to
// advance to the next region — instead of having its protection bits
// rewritten. Mutating VM_PROT_EXECUTE (the old blanket-NX) contradicts the
// region's max_protection and fingerprints the hook; skipping restricted
// intervals removes the mapping enumeration leak while leaving every other
// region byte-identical to stock. Regions that cannot be classified pass
// through UNCHANGED (protection is never mutated).
// A targeted probe reads the protection of the region that BACKS a specific
// function it names (detect_jb_payload passes &vm_region_64 as the search
// address and flags protection != VM_PROT_READ). Under Shadow the named symbol
// is rebound into ShadowCore, so the query lands in a restricted image. Neither
// answer is right: returning ShadowCore's executable __TEXT reveals injection
// (protection has EXECUTE), and skipping to the next region leaks a neighbouring
// mapping's protection. A stock process would find that function in a system
// library whose region reports VM_PROT_READ. So when an external caller's query
// address falls INSIDE a restricted region (a targeted point query, not the
// start-of-region step an enumeration loop makes), keep the region but present
// the stock read-only protection and drop the object name — the mapping looks
// like an ordinary system __TEXT instead of an injected or skipped region.
static kern_return_t (*original_vm_region_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_vm_region_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    vm_address_t queryAddr = address ? *address : 0;
    for(;;) {
        kern_return_t result = original_vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || flavor == VM_REGION_TOP_INFO || !shdw_addr_is_restricted((void *) *address)) {
            return result;
        }

        // Targeted point query: the caller's search address lies STRICTLY
        // inside the restricted region just returned (queryAddr > region start).
        // An enumeration loop instead steps to successive region starts, where
        // queryAddr == region start; excluding equality leaves enumeration on
        // the skip path so mappings are still hidden, while a point query at a
        // function address gets the stock read-only mapping. Present it as a
        // read-only system __TEXT rather than skipping (which would leak the
        // next region's protection) or exposing ShadowCore's executable text.
        if(flavor == VM_REGION_BASIC_INFO_64 && infoCnt && *infoCnt >= VM_REGION_BASIC_INFO_COUNT_64 &&
           *address < queryAddr && queryAddr < *address + *size) {
            vm_region_basic_info_64_t basic = (vm_region_basic_info_64_t) info;
            basic->protection = VM_PROT_READ;
            basic->max_protection = VM_PROT_READ;
            if(object_name && *object_name != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), *object_name);
                *object_name = MACH_PORT_NULL;
            }
            return result;
        }

        // Restricted region: drop the object-name send right this skipped
        // call returned (it is ours to deallocate) and advance the search
        // address past the region. vm_region_64 does NOT advance *address
        // itself — on success it returns the region CONTAINING the input
        // address with *address set to that region's START, and callers
        // advance by the returned size (the step every stock iteration loop
        // takes). Without the advance the re-call returns the same region
        // forever.
        if(object_name && *object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *object_name);
            *object_name = MACH_PORT_NULL;
        }

        *address += *size;
    }
}

static kern_return_t (*original_vm_region_recurse_64)(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_vm_region_recurse_64(vm_map_read_t target_task, vm_address_t* address, vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    for(;;) {
        kern_return_t result = original_vm_region_recurse_64(target_task, address, size, nesting_depth, info, infoCnt);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || !shdw_addr_is_restricted((void *) *address)) {
            return result;
        }

        // No *address auto-advance in this API: skip past the restricted
        // region manually (see replaced_vm_region_64).
        *address += *size;
    }
}

// mach_vm_region/mach_vm_region_recurse: the mach_vm_* twins of the two
// hooks above — same enumeration semantics over 64-bit address/size types,
// same skip policy (a returned region inside a restricted interval is
// SKIPPED and the original re-called to advance). The SDK's mach_vm.h is a
// stub, so the prototypes are declared here. NOTE: mach_vm_region takes the
// flavor BY VALUE (the ABI requires a value, not a pointer — a pointer
// earlier revision was an ABI bug: the hook passed a pointer where the
// kernel expects the int flavor, so the original call returned
// KERN_INVALID_ARGUMENT and the hiding never engaged, and callers of
// mach_vm_region got an error instead of region info).
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t (*original_mach_vm_region)(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);
static kern_return_t replaced_mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name) {
    for(;;) {
        kern_return_t result = original_mach_vm_region(target_task, address, size, flavor, info, infoCnt, object_name);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || flavor == VM_REGION_TOP_INFO || !shdw_addr_is_restricted((void *) *address)) {
            return result;
        }

        // Restricted region: drop the object-name send right this skipped
        // call returned (it is ours to deallocate) and advance to the next
        // region — same loop discipline as the vm_region_64 hook above
        // (mach_vm_region likewise does not advance *address on return).
        if(object_name && *object_name != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *object_name);
            *object_name = MACH_PORT_NULL;
        }

        *address += *size;
    }
}

extern kern_return_t mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t (*original_mach_vm_region_recurse)(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt);
static kern_return_t replaced_mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, natural_t* nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
    for(;;) {
        kern_return_t result = original_mach_vm_region_recurse(target_task, address, size, nesting_depth, info, infoCnt);

        if(result != KERN_SUCCESS) {
            return result;
        }

        if(!isCallerExternal() || !shdw_addr_is_restricted((void *) *address)) {
            return result;
        }

        // No *address auto-advance in this API: skip past the restricted
        // region manually (see replaced_vm_region_64).
        *address += *size;
    }
}

// vm_read_overwrite: the inline-patch integrity probe. Tamper detectors
// (BShield) read a hooked function's live bytes back out of the task and
// compare them to the expected prologue; ElleKit's inline lane left a branch
// stub at the function entry, so the comparison flags the hook. The original
// bytes are recoverable only because ShadowCore snapshots each prologue before
// patching (SHDWPrologueRecord). Run the real read, then for any subrange that
// overlaps a patched function, rewrite the caller's buffer with the pristine
// snapshot so the read returns stock bytes. Only external callers are filtered;
// Shadow's own reads (and cross-task reads) pass through with the live bytes.
static kern_return_t (*original_vm_read_overwrite)(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t* outsize);
static kern_return_t replaced_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t* outsize) {
    kern_return_t result = original_vm_read_overwrite(target_task, address, size, data, outsize);

    if(result != KERN_SUCCESS || !isCallerExternal() ||
       target_task != mach_task_self() || !data || size == 0) {
        return result;
    }

    // Rewrite any patched-function subranges in the freshly-read buffer with
    // their pristine prologue bytes.
    SHDWPrologueOverwrite(address, size, (uint8_t*)data);
    return result;
}

static void shdw_install_memory_hook(SHDWHookSession* hooks, void* target,
                                     void* replacement, void** original,
                                     NSString* symbol) {
    BOOL entrypointInstalled = [hooks hookFunction:target
                                   withReplacement:replacement
                                          outOldPtr:original];

    // A shared-cache caller can keep a direct import even when the entrypoint
    // route is available. The dlsym policy covers dynamic lookups; rebind the
    // already-loaded direct imports too.
    [hooks hookRebindSymbol:symbol
            withReplacement:replacement
                   outOldPtr:entrypointInstalled ? NULL : original];
}

void shdw_universal_memory(SHDWHookSession* hooks) {
    shdw_install_memory_hook(hooks, vm_region_64, replaced_vm_region_64,
                             (void **) &original_vm_region_64, @"vm_region_64");
    shdw_install_memory_hook(hooks, vm_region_recurse_64, replaced_vm_region_recurse_64,
                             (void **) &original_vm_region_recurse_64, @"vm_region_recurse_64");
    shdw_install_memory_hook(hooks, mach_vm_region, replaced_mach_vm_region,
                             (void **) &original_mach_vm_region, @"mach_vm_region");
    shdw_install_memory_hook(hooks, mach_vm_region_recurse, replaced_mach_vm_region_recurse,
                             (void **) &original_mach_vm_region_recurse, @"mach_vm_region_recurse");
    shdw_install_memory_hook(hooks, vm_read_overwrite, replaced_vm_read_overwrite,
                             (void **) &original_vm_read_overwrite, @"vm_read_overwrite");
}

// Symbol policy for the mem C-function group (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound mem
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees.
typedef struct {
    const char* name;
    void* replacement;
    void* const* original;
} shdw_mem_sym_policy_entry_t;

static const shdw_mem_sym_policy_entry_t shdw_mem_sym_policy_table[] = {
    { "mach_vm_region", (void*)&replaced_mach_vm_region, (void* const*)&original_mach_vm_region },
    { "mach_vm_region_recurse", (void*)&replaced_mach_vm_region_recurse, (void* const*)&original_mach_vm_region_recurse },
    { "vm_region_64", (void*)&replaced_vm_region_64, (void* const*)&original_vm_region_64 },
    { "vm_region_recurse_64", (void*)&replaced_vm_region_recurse_64, (void* const*)&original_vm_region_recurse_64 },
    { "vm_read_overwrite", (void*)&replaced_vm_read_overwrite, (void* const*)&original_vm_read_overwrite },
};

// Sorted index over the table, built on first use: dlsym policy lookups miss
// for every ordinary symbol and scanned the whole table linearly.
#define SHDW_MEM_SYM_COUNT (sizeof(shdw_mem_sym_policy_table) / sizeof(shdw_mem_sym_policy_table[0]))

static int shdw_mem_sym_compare(const void* a, const void* b) {
    const shdw_mem_sym_policy_entry_t* ra = *(const shdw_mem_sym_policy_entry_t* const*)a;
    const shdw_mem_sym_policy_entry_t* rb = *(const shdw_mem_sym_policy_entry_t* const*)b;
    return strcmp(ra->name, rb->name);
}

static const shdw_mem_sym_policy_entry_t* shdw_mem_sym_sorted[SHDW_MEM_SYM_COUNT];
static dispatch_once_t shdw_mem_sym_sort_once;

static void shdw_mem_sym_sort(void* unused) {
    (void)unused;

    for(size_t i = 0; i < SHDW_MEM_SYM_COUNT; i++) {
        shdw_mem_sym_sorted[i] = &shdw_mem_sym_policy_table[i];
    }

    qsort(shdw_mem_sym_sorted, SHDW_MEM_SYM_COUNT, sizeof(shdw_mem_sym_sorted[0]), shdw_mem_sym_compare);
}

void* shdw_sym_policy_lookup_mem(const char* name) {
    if(!name) {
        return NULL;
    }

    dispatch_once_f(&shdw_mem_sym_sort_once, NULL, shdw_mem_sym_sort);

    shdw_mem_sym_policy_entry_t key = { name, NULL, NULL };
    const shdw_mem_sym_policy_entry_t* keyp = &key;
    const shdw_mem_sym_policy_entry_t** hit = bsearch(&keyp, shdw_mem_sym_sorted, SHDW_MEM_SYM_COUNT, sizeof(shdw_mem_sym_sorted[0]), shdw_mem_sym_compare);

    if(!hit) {
        return NULL;
    }

    const shdw_mem_sym_policy_entry_t* d = *hit;

    if(d->original && *d->original == NULL) {
        return NULL;  // symbol not installed
    }

    return d->replacement;
}
