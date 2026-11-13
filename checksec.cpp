#include "checksec.h"

#include <pe-parse/parse.h>
#include <uthenticode.h>

#include <cstring>
#include <ostream>
#include <vector>
#include <optional>

#define REPORT_EXPLAIN(presence, description, explanation) \
    { MitigationPresence::presence, impl::description, explanation }
#define REPORT(presence, description) REPORT_EXPLAIN(presence, description, std::nullopt)

namespace checksec {

namespace {

// IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
constexpr std::uint32_t kImageDebugTypeExDllCharacteristics = 20;

enum class ExtendedDllCharacteristicsStatus {
    Read,       // The extended DLL characteristics were read in full.
    Absent,     // The image contains no EX_DLLCHARACTERISTICS debug directory.
    Malformed,  // A matching debug directory exists but its data is unsafe.
};

/**
 * Locate the EX_DLLCHARACTERISTICS debug directory and read the extended DLL
 * characteristics it points to.
 *
 * `debugDirectories` is the raw, already-bounds-checked debug directory blob
 * returned by pe-parse; it contains a sequence of `debug_dir_entry` structures.
 * Every dereference is additionally checked against the underlying file buffer
 * so that a truncated or otherwise malformed image can never cause an
 * out-of-bounds read.
 *
 * @return an ExtendedDllCharacteristicsStatus describing whether the extended
 *  DLL characteristics were read, were absent, or could not be read safely
 */
ExtendedDllCharacteristicsStatus readExtendedDllCharacteristics(
    peparse::parsed_pe* pe, const std::vector<std::uint8_t>& debugDirectories,
    std::uint16_t& extendedDllCharacteristics) {
    auto* fileBuffer = pe->fileBuffer;
    const auto fileBase = reinterpret_cast<std::uintptr_t>(fileBuffer->buf);
    const std::uint32_t fileLength = fileBuffer->bufLen;

    const std::size_t entryCount = debugDirectories.size() / sizeof(peparse::debug_dir_entry);
    for (std::size_t i = 0; i < entryCount; ++i) {
        peparse::debug_dir_entry debugDir{};
        // Only whole debug directory entries are iterated; a trailing partial
        // entry is ignored rather than read past the blob's bounds.
        std::memcpy(&debugDir, debugDirectories.data() + (i * sizeof(peparse::debug_dir_entry)),
                    sizeof(debugDir));

        if (debugDir.Type != kImageDebugTypeExDllCharacteristics) {
            continue;
        }

        if (debugDir.PointerToRawData == 0) {
            continue;
        }

        // The EX_DLLCHARACTERISTICS payload must contain the full
        // extended DLL characteristics value (a uint16_t). A declared
        // SizeOfData smaller than that implies a truncated entry. Some
        // linkers emit SizeOfData == 0, in which case the file-buffer span
        // check below is the authoritative validation.
        const std::uint32_t requiredSize = sizeof(extendedDllCharacteristics);
        if (debugDir.SizeOfData != 0 && debugDir.SizeOfData < requiredSize) {
            std::cerr << "Warn: undersized extended DLL characteristics data"
                      << "\n";
            return ExtendedDllCharacteristicsStatus::Malformed;
        }

        // Check the full span (not just the starting pointer) before
        // dereferencing. Do the arithmetic in uintptr_t to avoid pointer
        // overflow, and reject offsets that wrap or leave the file buffer.
        const std::uintptr_t dataStart = fileBase + debugDir.PointerToRawData;
        if (dataStart < fileBase || dataStart > fileBase + fileLength) {
            std::cerr << "Warn: extended DLL characteristics pointer is out of bounds"
                      << "\n";
            return ExtendedDllCharacteristicsStatus::Malformed;
        }

        const std::uint32_t remaining =
            static_cast<std::uint32_t>(fileBase + fileLength - dataStart);
        if (remaining < sizeof(extendedDllCharacteristics)) {
            std::cerr << "Warn: truncated extended DLL characteristics data"
                      << "\n";
            return ExtendedDllCharacteristicsStatus::Malformed;
        }

        std::memcpy(&extendedDllCharacteristics, reinterpret_cast<const void*>(dataStart),
                    sizeof(extendedDllCharacteristics));
        return ExtendedDllCharacteristicsStatus::Read;
    }

    // No EX_DLLCHARACTERISTICS debug directory: genuinely not present, which is
    // distinct from a malformed one.
    return ExtendedDllCharacteristicsStatus::Absent;
}

}  // namespace

Checksec::Checksec(std::string filepath) : filepath_(filepath), loadedImage_(filepath) {
    peparse::nt_header_32 nt = loadedImage_.get()->peHeader.nt;
    peparse::file_header* imageFileHeader = &(nt.FileHeader);

    targetMachine_ = imageFileHeader->Machine;
    imageCharacteristics_ = imageFileHeader->Characteristics;
    std::vector<std::uint8_t> loadConfigData;
    std::vector<std::uint8_t> debugDirectories;

    // Check whether we need a 32 or 32+ optional header.
    if (nt.OptionalMagic == peparse::NT_OPTIONAL_64_MAGIC) {
        peparse::optional_header_64* optionalHeader = &(nt.OptionalHeader64);
        dllCharacteristics_ = optionalHeader->DllCharacteristics;
        if (optionalHeader->NumberOfRvaAndSizes < peparse::DIR_COM_DESCRIPTOR + 1) {
            std::cerr << "Warn: short image data directory vector (no CLR info?)"
                      << "\n";
            return;
        }
        clrConfig_ = optionalHeader->DataDirectory[peparse::DIR_COM_DESCRIPTOR];

        // Warn and return early if the image data directory vector
        // is too short to contain a reference to the DIR_LOAD_CONFIG.
        if (optionalHeader->NumberOfRvaAndSizes < peparse::DIR_LOAD_CONFIG + 1) {
            std::cerr << "Warn: short image data directory vector (no load config?)"
                      << "\n";
            return;
        }

        if (!peparse::GetDataDirectoryEntry(loadedImage_.get(), peparse::DIR_LOAD_CONFIG,
                                            loadConfigData)) {
            std::cerr << "Warn: No load config in the PE"
                      << "\n";
            return;
        }
        peparse::image_load_config_64 loadConfig{};
        if (loadConfigData.size() > sizeof(loadConfig)) {
            std::cerr << "Warn: large load config, probably contains undocumented "
                         "fields"
                      << "\n";
        } else if (loadConfigData.size() < sizeof(loadConfig)) {
            std::cerr << "Warn: undersized load config, probably missing fields"
                      << "\n";
        }
        auto size = std::min(loadConfigData.size(), sizeof(loadConfig));
        memcpy(&loadConfig, loadConfigData.data(), size);
        loadConfigSize_ = loadConfigData.size();
        loadConfigGuardFlags_ = loadConfig.GuardFlags;
        loadConfigSecurityCookie_ = loadConfig.SecurityCookie;
        loadConfigSEHandlerTable_ = loadConfig.SEHandlerTable;
        loadConfigSEHandlerCount_ = loadConfig.SEHandlerCount;

        // Iterate over debug directories
        if (!peparse::GetDataDirectoryEntry(loadedImage_.get(), peparse::DIR_DEBUG,
                                            debugDirectories)) {
            std::cerr << "Warn: No debug directories"
                      << "\n";
            return;
        }

        extendedDllCharacteristicsValid_ =
            readExtendedDllCharacteristics(loadedImage_.get(), debugDirectories,
                                           extendedDllCharacteristics_) !=
            ExtendedDllCharacteristicsStatus::Malformed;
    } else {
        peparse::optional_header_32* optionalHeader = &(nt.OptionalHeader);
        dllCharacteristics_ = optionalHeader->DllCharacteristics;
        if (optionalHeader->NumberOfRvaAndSizes < peparse::DIR_COM_DESCRIPTOR + 1) {
            std::cerr << "Warn: short image data directory vector (no CLR info?)"
                      << "\n";
            return;
        }
        clrConfig_ = optionalHeader->DataDirectory[peparse::DIR_COM_DESCRIPTOR];
        // Warn and return early if the image data directory vector
        // is too short to contain a reference to the DIR_LOAD_CONFIG.
        if (optionalHeader->NumberOfRvaAndSizes < peparse::DIR_LOAD_CONFIG + 1) {
            std::cerr << "Warn: short image data directory vector (no load config?)"
                      << "\n";
            return;
        }

        if (!peparse::GetDataDirectoryEntry(loadedImage_.get(), peparse::DIR_LOAD_CONFIG,
                                            loadConfigData)) {
            std::cerr << "Warn: No load config in the PE"
                      << "\n";
            return;
        }
        peparse::image_load_config_32 loadConfig{};
        if (loadConfigData.size() > sizeof(loadConfig)) {
            std::cerr << "Warn: large load config, probably contains undocumented "
                         "fields"
                      << "\n";
        } else if (loadConfigData.size() < sizeof(loadConfig)) {
            std::cerr << "Warn: undersized load config, probably missing fields"
                      << "\n";
        }
        auto size = std::min(loadConfigData.size(), sizeof(loadConfig));
        memcpy(&loadConfig, loadConfigData.data(), size);
        loadConfigSize_ = loadConfigData.size();
        loadConfigGuardFlags_ = loadConfig.GuardFlags;
        loadConfigSecurityCookie_ = loadConfig.SecurityCookie;
        loadConfigSEHandlerTable_ = loadConfig.SEHandlerTable;
        loadConfigSEHandlerCount_ = loadConfig.SEHandlerCount;

        if (!peparse::GetDataDirectoryEntry(loadedImage_.get(), peparse::DIR_DEBUG,
                                            debugDirectories)) {
            std::cerr << "Warn: No debug directories"
                      << "\n";
            return;
        }

        extendedDllCharacteristicsValid_ =
            readExtendedDllCharacteristics(loadedImage_.get(), debugDirectories,
                                           extendedDllCharacteristics_) !=
            ExtendedDllCharacteristicsStatus::Malformed;
    }
}

const MitigationReport Checksec::isDynamicBase() const {
    if (dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        return REPORT(Present, kDynamicBaseDescription);
    } else {
        return REPORT(NotPresent, kDynamicBaseDescription);
    }
}

const MitigationReport Checksec::isASLR() const {
    // A binary is ASLR'd if:
    // * It was linked with /DYNAMICBASE and has *not* had its relocation
    // entries stripped, or
    // * It's managed by the CLR, which is always ASLR'd.
    if (isDynamicBase()) {
        if (imageCharacteristics_ & peparse::IMAGE_FILE_RELOCS_STRIPPED) {
            return REPORT_EXPLAIN(NotPresent, kASLRDescription,
                                  "Image has stripped relocations, making ASLR impossible.");
        }
        return REPORT(Present, kASLRDescription);
    } else if (isDotNET()) {
        return REPORT_EXPLAIN(Present, kASLRDescription,
                              ".NET binaries have ASLR via the .NET runtime.");
    } else {
        return REPORT(NotPresent, kASLRDescription);
    }
}

const MitigationReport Checksec::isHighEntropyVA() const {
    // NOTE(ww): Set by /HIGHENTROPYVA, but not exposed anywhere as a constant.
    // Only relevant on 64-bit machines with 64-bit images.
    // NOTE(ww): Additionally, don't count a binary as high-entropy capable
    // if it isn't also ASLR'd.
    if ((dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) && isASLR()) {
        return REPORT(Present, kHighEntropyVADescription);
    } else {
        return REPORT(NotPresent, kHighEntropyVADescription);
    }
}

const MitigationReport Checksec::isForceIntegrity() const {
    if (dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
        return REPORT(Present, kForceIntegrityDescription);
    } else {
        return REPORT(NotPresent, kForceIntegrityDescription);
    }
}

const MitigationReport Checksec::isNX() const {
    if ((dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) {
        return REPORT(Present, kNXDescription);
    } else if (isDotNET()) {
        return REPORT_EXPLAIN(Present, kNXDescription,
                              ".NET binaries have DEP via the .NET runtime.");
    } else {
        return REPORT(NotPresent, kNXDescription);
    }
}

const MitigationReport Checksec::isIsolation() const {
    if (!(dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)) {
        return REPORT(Present, kIsolationDescription);
    } else {
        return REPORT(NotPresent, kIsolationDescription);
    }
}

const MitigationReport Checksec::isSEH() const {
    if (!(dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_NO_SEH)) {
        return REPORT(Present, kSEHDescription);
    } else {
        return REPORT(NotPresent, kSEHDescription);
    }
}

const MitigationReport Checksec::isCFG() const {
    // NOTE(ww): See the /GUARD:CF docs: /DYNAMICBASE is required.
    // We check for ASLR instead, since just checking for /DYNAMICBASE
    // could result in a false-positive (with stripped relocations).
    if (!isASLR()) {
        return REPORT_EXPLAIN(NotPresent, kCFGDescription,
                              "Control Flow Guard requires functional ASLR.");
    }

    if (dllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        return REPORT(Present, kCFGDescription);
    } else {
        return REPORT(NotPresent, kCFGDescription);
    }
}

const MitigationReport Checksec::isAuthenticode() const {
    if (uthenticode::verify(loadedImage_.get())) {
        return REPORT(Present, kAuthenticodeDescription);
    } else {
        return REPORT(NotPresent, kAuthenticodeDescription);
    }
}

const MitigationReport Checksec::isRFG() const {
    // NOTE(ww): a load config under 92/148 bytes implies the absence of the
    // GuardFlags field. See:
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#load-configuration-layout
    if (loadConfigSize_ < 148 &&
        !(imageCharacteristics_ & peparse::IMAGE_FILE_32BIT_MACHINE && loadConfigSize_ >= 92)) {
        return REPORT_EXPLAIN(NotPresent, kRFGDescription,
                              "Image load config is too short to contain RFG "
                              "configuration fields.");
    }

    // https://xlab.tencent.com/en/2016/11/02/return-flow-guard/
    if ((loadConfigGuardFlags_ & 0x00020000) &&
        (loadConfigGuardFlags_ & 0x00040000 || loadConfigGuardFlags_ & 0x00080000)) {
        return REPORT(Present, kRFGDescription);
    } else {
        return REPORT(NotPresent, kRFGDescription);
    }
}

const MitigationReport Checksec::isSafeSEH() const {
    if (targetMachine_ != peparse::IMAGE_FILE_MACHINE_I386) {
        return REPORT_EXPLAIN(NotApplicable, kSafeSEHDescription,
                              "The SafeSEH mitigation only applies to x86_32 binaries.");
    }

    // NOTE(ww): a load config under 72/112 bytes implies the absence of the
    // SafeSEH fields.
    if (loadConfigSize_ < 112 &&
        !(imageCharacteristics_ & peparse::IMAGE_FILE_32BIT_MACHINE && loadConfigSize_ >= 72)) {
        return REPORT_EXPLAIN(NotPresent, kSafeSEHDescription,
                              "Image load config is too short to contain a SE handler table.");
    }

    if (isSEH() && loadConfigSEHandlerTable_ != 0 && loadConfigSEHandlerCount_ != 0) {
        return REPORT(Present, kSafeSEHDescription);
    } else {
        return REPORT(NotPresent, kSafeSEHDescription);
    }
}

const MitigationReport Checksec::isGS() const {
    // NOTE(ww): a load config under 64/96 bytes implies the absence of the
    // SecurityCookie field.
    if (loadConfigSize_ < 96 &&
        !(imageCharacteristics_ & peparse::IMAGE_FILE_32BIT_MACHINE && loadConfigSize_ >= 64)) {
        return REPORT_EXPLAIN(NotPresent, kGSDescription,
                              "Image load config is too short to contain a GS security cookie.");
    }

    if (loadConfigSecurityCookie_ != 0) {
        return REPORT(Present, kGSDescription);
    } else {
        return REPORT(NotPresent, kGSDescription);
    }
}

const MitigationReport Checksec::isDotNET() const {
    if (clrConfig_.VirtualAddress != 0) {
        return REPORT(Present, kDotNETDescription);
    } else {
        return REPORT(NotPresent, kDotNETDescription);
    }
}

const MitigationReport Checksec::isCetCompat() const {
    if (!extendedDllCharacteristicsValid_) {
        return REPORT_EXPLAIN(NotImplemented, kCetDescription,
                              "Extended DLL characteristics could not be read: the "
                              "debug directory is missing or malformed.");
    }

    if (extendedDllCharacteristics_ & peparse::IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) {
        return REPORT(Present, kCetDescription);
    } else {
        return REPORT(NotPresent, kCetDescription);
    }
}

}  // namespace checksec
