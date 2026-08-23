#import "MITargetSymbolResolver.h"

#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>

NSErrorDomain const MITargetSymbolResolverErrorDomain = @"MITargetSymbolResolverErrorDomain";

// A symbol table larger than this is not something we are prepared to pull
// across a process boundary in one read. Nothing we resolve lives in an image
// remotely near it — libsystem_pthread's table is a few thousand entries — so
// the cap exists to bound a corrupt or hostile header, not to serve a real case.
static const uint64_t MITargetSymbolResolverMaximumTableSize = 64ull * 1024 * 1024;

// Longest symbol name we will compare. Names in the images this resolver reads
// are short; the bound just keeps the string window finite.
static const uint32_t MITargetSymbolResolverMaximumSymbolNameLength = 512;

// dyld has kept `dyld_all_image_infos` append-only for a long time, but the
// fields this resolver needs did not all exist from the start. Version 15 is
// the floor at which `sharedCacheSlide` and `sharedCacheBaseAddress` are both
// present; every OS that can host a simulator reports far higher (17 measured).
static const uint32_t MITargetSymbolResolverMinimumAllImageInfosVersion = 15;

static NSError *MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorCode code, NSString *format, ...) NS_FORMAT_FUNCTION(2, 3);
static NSError *MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorCode code, NSString *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    return [NSError errorWithDomain:MITargetSymbolResolverErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

@interface MITargetSymbolResolverImage : NSObject
@property (nonatomic, copy) NSString *path;
@property (nonatomic) uint64_t loadAddress;
@end

@implementation MITargetSymbolResolverImage
@end

@implementation MITargetSymbolResolver {
    MIMemoryReader _memoryReader;
    NSArray<MITargetSymbolResolverImage *> *_images;
}

#pragma mark - Construction

+ (nullable instancetype)resolverForTask:(mach_port_t)task error:(NSError **)error {
    struct task_dyld_info dyldInfo;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if (kr != KERN_SUCCESS) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorDyldInfoUnavailable,
                                                     @"task_info(TASK_DYLD_INFO) failed: %s", mach_error_string(kr));
        }
        return nil;
    }

    MIMemoryReader reader = ^BOOL(uint64_t address, void *buffer, size_t size) {
        mach_vm_size_t bytesRead = 0;
        kern_return_t readResult = mach_vm_read_overwrite(task, (mach_vm_address_t)address, (mach_vm_size_t)size,
                                                          (mach_vm_address_t)buffer, &bytesRead);
        return readResult == KERN_SUCCESS && bytesRead == size;
    };

    return [self resolverWithMemoryReader:reader
                     allImageInfosAddress:(uint64_t)dyldInfo.all_image_info_addr
                                    error:error];
}

+ (nullable instancetype)resolverWithMemoryReader:(MIMemoryReader)memoryReader
                             allImageInfosAddress:(uint64_t)allImageInfosAddress
                                            error:(NSError **)error {
    MITargetSymbolResolver *resolver = [[self alloc] init];
    resolver->_memoryReader = [memoryReader copy];
    if (![resolver loadImageListFromAllImageInfosAddress:allImageInfosAddress error:error]) {
        return nil;
    }
    return resolver;
}

- (BOOL)loadImageListFromAllImageInfosAddress:(uint64_t)allImageInfosAddress error:(NSError **)error {
    if (allImageInfosAddress == 0) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorAllImageInfosUnreadable,
                                                     @"the target published no dyld_all_image_infos address");
        }
        return NO;
    }

    struct dyld_all_image_infos allImageInfos;
    if (!_memoryReader(allImageInfosAddress, &allImageInfos, sizeof(allImageInfos))) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorAllImageInfosUnreadable,
                                                     @"could not read dyld_all_image_infos at 0x%llx", allImageInfosAddress);
        }
        return NO;
    }

    if (allImageInfos.version < MITargetSymbolResolverMinimumAllImageInfosVersion) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorAllImageInfosUnreadable,
                                                     @"dyld_all_image_infos version %u is below the supported minimum %u",
                                                     allImageInfos.version, MITargetSymbolResolverMinimumAllImageInfosVersion);
        }
        return NO;
    }

    _sharedCacheSlide = (uint64_t)allImageInfos.sharedCacheSlide;
    _sharedCacheBaseAddress = (uint64_t)allImageInfos.sharedCacheBaseAddress;

    uint32_t imageCount = allImageInfos.infoArrayCount;
    uint64_t infoArrayAddress = (uint64_t)allImageInfos.infoArray;
    if (imageCount == 0 || infoArrayAddress == 0) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorImageListUnreadable,
                                                     @"the target reported %u images at 0x%llx", imageCount, infoArrayAddress);
        }
        return NO;
    }

    NSMutableArray<MITargetSymbolResolverImage *> *images = [NSMutableArray arrayWithCapacity:imageCount];
    for (uint32_t index = 0; index < imageCount; index++) {
        struct dyld_image_info info;
        uint64_t slot = infoArrayAddress + (uint64_t)index * sizeof(info);
        if (!_memoryReader(slot, &info, sizeof(info))) {
            // A single unreadable entry is not fatal: dyld mutates this array
            // while we walk it, so a torn read here means that one image is
            // in flux, not that the target is unusable.
            continue;
        }

        NSString *path = [self stringAtAddress:(uint64_t)info.imageFilePath maximumLength:PATH_MAX];
        if (path.length == 0) {
            continue;
        }

        MITargetSymbolResolverImage *image = [[MITargetSymbolResolverImage alloc] init];
        image.path = path;
        image.loadAddress = (uint64_t)info.imageLoadAddress;
        [images addObject:image];
    }

    if (images.count == 0) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorImageListUnreadable,
                                                     @"none of the target's %u images could be read", imageCount);
        }
        return NO;
    }

    _images = [images copy];

    // Architecture comes from an image the target actually loaded. Reading it
    // from the injector would defeat the purpose: an arm64e injector routinely
    // drives an arm64 target, and that difference decides PAC signing.
    struct mach_header_64 header;
    if (_memoryReader(images.firstObject.loadAddress, &header, sizeof(header)) &&
        (header.magic == MH_MAGIC_64 || header.magic == MH_CIGAM_64)) {
        _targetCPUType = header.cputype;
        _targetCPUSubtype = header.cpusubtype;
    }

    return YES;
}

#pragma mark - Image lookup

- (NSArray<NSString *> *)imagePaths {
    NSMutableArray<NSString *> *paths = [NSMutableArray arrayWithCapacity:_images.count];
    for (MITargetSymbolResolverImage *image in _images) {
        [paths addObject:image.path];
    }
    return [paths copy];
}

- (BOOL)isSimulatorTarget {
    for (MITargetSymbolResolverImage *image in _images) {
        if ([image.path containsString:@"/RuntimeRoot/"] || [image.path containsString:@".simruntime/"]) {
            return YES;
        }
    }
    return NO;
}

- (nullable MITargetSymbolResolverImage *)imageWithPathSuffix:(NSString *)suffix {
    for (MITargetSymbolResolverImage *image in _images) {
        if ([image.path hasSuffix:suffix]) {
            return image;
        }
    }
    return nil;
}

- (uint64_t)loadAddressOfImageWithPath:(NSString *)imagePathSuffix {
    return [self imageWithPathSuffix:imagePathSuffix].loadAddress ?: 0;
}

#pragma mark - Symbol lookup

- (uint64_t)addressOfSymbol:(NSString *)symbolName
            inImageWithPath:(NSString *)imagePathSuffix
                      error:(NSError **)error {
    MITargetSymbolResolverImage *image = [self imageWithPathSuffix:imagePathSuffix];
    if (!image) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorImageNotFound,
                                                     @"the target has no image whose path ends in %@", imagePathSuffix);
        }
        return 0;
    }

    struct mach_header_64 header;
    if (!_memoryReader(image.loadAddress, &header, sizeof(header)) ||
        (header.magic != MH_MAGIC_64 && header.magic != MH_CIGAM_64)) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorMachHeaderUnreadable,
                                                     @"no readable Mach-O header at 0x%llx for %@", image.loadAddress, image.path);
        }
        return 0;
    }

    void *loadCommands = malloc(header.sizeofcmds);
    if (!loadCommands) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorMachHeaderUnreadable,
                                                     @"could not allocate %u bytes for %@'s load commands", header.sizeofcmds, image.path);
        }
        return 0;
    }

    uint64_t address = 0;
    if (_memoryReader(image.loadAddress + sizeof(header), loadCommands, header.sizeofcmds)) {
        address = [self addressOfSymbol:symbolName
                                inImage:image
                                 header:&header
                           loadCommands:loadCommands
                                  error:error];
    } else if (error) {
        *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorMachHeaderUnreadable,
                                                 @"could not read %@'s load commands", image.path);
    }

    free(loadCommands);
    return address;
}

- (uint64_t)addressOfSymbol:(NSString *)symbolName
                    inImage:(MITargetSymbolResolverImage *)image
                     header:(const struct mach_header_64 *)header
               loadCommands:(const void *)loadCommands
                      error:(NSError **)error {
    // Mach-O records file offsets for the symbol table but virtual addresses
    // for segments, so translating one into the other needs both __TEXT (to
    // recover the slide dyld applied) and __LINKEDIT (to convert a file offset
    // into the address that data ended up at).
    uint64_t textVirtualAddress = UINT64_MAX;
    uint64_t linkeditVirtualAddress = 0;
    uint64_t linkeditFileOffset = 0;
    BOOL hasLinkedit = NO;
    const struct symtab_command *symbolTableCommand = NULL;

    const uint8_t *cursor = loadCommands;
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) {
            break;
        }
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command) || (size_t)(end - cursor) < command->cmdsize) {
            break;
        }

        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_TEXT, sizeof(segment->segname)) == 0) {
                textVirtualAddress = segment->vmaddr;
            } else if (strncmp(segment->segname, SEG_LINKEDIT, sizeof(segment->segname)) == 0) {
                linkeditVirtualAddress = segment->vmaddr;
                linkeditFileOffset = segment->fileoff;
                hasLinkedit = YES;
            }
        } else if (command->cmd == LC_SYMTAB && command->cmdsize >= sizeof(struct symtab_command)) {
            symbolTableCommand = (const struct symtab_command *)command;
        }

        cursor += command->cmdsize;
    }

    if (textVirtualAddress == UINT64_MAX || !hasLinkedit || symbolTableCommand == NULL ||
        symbolTableCommand->nsyms == 0 || symbolTableCommand->strsize == 0) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorSymbolTableUnavailable,
                                                     @"%@ carries no readable symbol table", image.path);
        }
        return 0;
    }

    uint64_t slide = image.loadAddress - textVirtualAddress;
    uint64_t linkeditAddress = linkeditVirtualAddress + slide;

    uint64_t symbolTableSize = (uint64_t)symbolTableCommand->nsyms * sizeof(struct nlist_64);
    if (symbolTableSize > MITargetSymbolResolverMaximumTableSize) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorSymbolTableUnavailable,
                                                     @"%@ claims %u symbols, which is not plausible",
                                                     image.path, symbolTableCommand->nsyms);
        }
        return 0;
    }

    struct nlist_64 *symbols = malloc((size_t)symbolTableSize);
    if (!symbols) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorSymbolTableUnavailable,
                                                     @"could not allocate %llu bytes for %@'s symbol table", symbolTableSize, image.path);
        }
        return 0;
    }

    // Everything the error paths jump over has to be declared up front: `goto`
    // may not skip an initialisation, and under ARC that includes every object.
    uint64_t address = 0;
    char *strings = NULL;
    NSString *mangled = nil;
    const char *wanted = NULL;

    if (!_memoryReader(linkeditAddress + (symbolTableCommand->symoff - linkeditFileOffset), symbols, (size_t)symbolTableSize)) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorSymbolTableUnavailable,
                                                     @"could not read %@'s symbol table out of the target", image.path);
        }
        goto cleanup;
    }

    // The string table cannot be pulled across in bulk, and not merely because
    // of its size. An image served out of a dyld shared cache shares one string
    // table with every image in that cache — 387 MB for libsystem_pthread — and
    // the cache builder merges and dedupes names, so this image's own names are
    // scattered the length of it: measured span 378 MB for 7520 symbols. There
    // is no window to read.
    //
    // So compare name by name instead. Only `strlen(wanted) + 1` bytes are ever
    // needed per symbol — enough to tell a match from a prefix — and almost
    // every candidate is rejected on its first character.
    uint64_t stringTableAddress = linkeditAddress + (symbolTableCommand->stroff - linkeditFileOffset);
    mangled = [@"_" stringByAppendingString:symbolName];
    wanted = mangled.UTF8String;
    size_t wantedLength = strlen(wanted);
    if (wantedLength + 1 > MITargetSymbolResolverMaximumSymbolNameLength) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorSymbolNotFound,
                                                     @"symbol name %@ is longer than this resolver compares", symbolName);
        }
        goto cleanup;
    }

    strings = malloc(MITargetSymbolResolverMaximumSymbolNameLength);
    if (!strings) {
        if (error) {
            *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorSymbolTableUnavailable,
                                                     @"could not allocate a name comparison buffer");
        }
        goto cleanup;
    }

    for (uint32_t index = 0; index < symbolTableCommand->nsyms; index++) {
        const struct nlist_64 *symbol = &symbols[index];
        if (symbol->n_value == 0 || (symbol->n_type & N_STAB) != 0) {
            continue;
        }
        uint32_t stringOffset = symbol->n_un.n_strx;
        if (stringOffset == 0 || stringOffset >= symbolTableCommand->strsize) {
            continue;
        }
        // Never read past the table's own end, however short that leaves us:
        // a name that cannot fit the one we want is not the one we want.
        uint64_t available = (uint64_t)symbolTableCommand->strsize - stringOffset;
        if (available < wantedLength + 1) {
            continue;
        }
        if (!_memoryReader(stringTableAddress + stringOffset, strings, wantedLength + 1)) {
            continue;
        }
        if (memcmp(strings, wanted, wantedLength) == 0 && strings[wantedLength] == '\0') {
            address = symbol->n_value + slide;
            break;
        }
    }

    if (address == 0 && error) {
        *error = MITargetSymbolResolverErrorMake(MITargetSymbolResolverErrorSymbolNotFound,
                                                 @"%@ does not export %@", image.path, symbolName);
    }

cleanup:
    free(symbols);
    free(strings);
    return address;
}

#pragma mark - Helpers

- (nullable NSString *)stringAtAddress:(uint64_t)address maximumLength:(size_t)maximumLength {
    if (address == 0) {
        return nil;
    }
    char *buffer = calloc(1, maximumLength + 1);
    if (!buffer) {
        return nil;
    }

    // Strings sit at the end of their page as often as not, so a single read of
    // the full length would fail on an unmapped neighbour. Halve until it fits.
    size_t length = maximumLength;
    BOOL didRead = NO;
    while (length >= 16) {
        if (_memoryReader(address, buffer, length)) {
            didRead = YES;
            break;
        }
        length /= 2;
    }

    NSString *string = nil;
    if (didRead) {
        buffer[length] = '\0';
        string = [NSString stringWithUTF8String:buffer];
    }
    free(buffer);
    return string;
}

@end
