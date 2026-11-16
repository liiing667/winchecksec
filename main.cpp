#include "checksec.h"
#include "vendor/argh.h"
#include "vendor/json.hpp"

#include <algorithm>

using ordered_json = nlohmann::ordered_json;

namespace {

/**
 * Exit codes, in increasing order of severity. When multiple input files are
 * given, the process exits with the code of the most severe per-file outcome.
 */
enum ExitCode {
    Ok = 0,               /**< All inputs parsed; every signed input verified */
    UsageError = 1,       /**< Bad command-line usage */
    Unsigned = 2,         /**< At least one input has no Authenticode signature */
    InvalidSignature = 3, /**< At least one input has an invalid Authenticode signature */
    ParseError = 4,       /**< At least one input could not be parsed as a PE */
    GeneralError = 5,     /**< At least one input failed with an unexpected error */
};

/**
 * Running tally of per-file outcomes, shared by the JSON and text reports.
 */
struct Summary {
    std::size_t ok = 0;
    std::size_t unsigned_ = 0;
    std::size_t invalidSignature = 0;
    std::size_t failed = 0;

    std::size_t total() const { return ok + unsigned_ + invalidSignature + failed; }
};

void to_json(ordered_json& j, const Summary& s) {
    j = ordered_json{
        {"total", s.total()},
        {"ok", s.ok},
        {"unsigned", s.unsigned_},
        {"invalidSignature", s.invalidSignature},
        {"failed", s.failed},
    };
}

std::ostream& operator<<(std::ostream& os, const Summary& s) {
    os << "Summary: " << s.total() << " file(s): " << s.ok << " ok, " << s.unsigned_
       << " unsigned, " << s.invalidSignature << " invalid signature(s), " << s.failed
       << " failed";
    return os;
}

}  // namespace

namespace checksec {
void to_json(ordered_json& j, const MitigationPresence& p) {
    switch (p) {
        default: {
            j = "Unknown";
            break;
        }
        case MitigationPresence::Present: {
            j = "Present";
            break;
        }
        case MitigationPresence::NotPresent: {
            j = "NotPresent";
            break;
        }
        case MitigationPresence::NotApplicable: {
            j = "NotApplicable";
            break;
        }
        case MitigationPresence::NotImplemented: {
            j = "NotImplemented";
            break;
        }
    }
}

void to_json(ordered_json& j, const MitigationReport& r) {
    j = ordered_json{
        {"presence", r.presence},
        {"description", r.description},
    };

    if (r.explanation) {
        j["explanation"] = r.explanation.value();
    }
}

void to_json(ordered_json& j, const Checksec& c) {
    j = ordered_json{
        {"path", c.filepath()},
        {
            "mitigations",
            {
                {"dynamicBase", c.isDynamicBase()},
                {"aslr", c.isASLR()},
                {"highEntropyVA", c.isHighEntropyVA()},
                {"forceIntegrity", c.isForceIntegrity()},
                {"isolation", c.isIsolation()},
                {"nx", c.isNX()},
                {"seh", c.isSEH()},
                {"cfg", c.isCFG()},
                {"rfg", c.isRFG()},
                {"safeSEH", c.isSafeSEH()},
                {"gs", c.isGS()},
                {"authenticode", c.isAuthenticode()},
                {"dotNET", c.isDotNET()},
                {"CetCompat", c.isCetCompat()},
            },
        },
    };
}

std::ostream& operator<<(std::ostream& os, Checksec& self) {
    ordered_json j(self);
    os << "Dynamic Base    : " << j["mitigations"]["dynamicBase"]["presence"] << "\n";
    os << "ASLR            : " << j["mitigations"]["aslr"]["presence"] << "\n";
    os << "High Entropy VA : " << j["mitigations"]["highEntropyVA"]["presence"] << "\n";
    os << "Force Integrity : " << j["mitigations"]["forceIntegrity"]["presence"] << "\n";
    os << "Isolation       : " << j["mitigations"]["isolation"]["presence"] << "\n";
    os << "NX              : " << j["mitigations"]["nx"]["presence"] << "\n";
    os << "SEH             : " << j["mitigations"]["seh"]["presence"] << "\n";
    os << "CFG             : " << j["mitigations"]["cfg"]["presence"] << "\n";
    os << "RFG             : " << j["mitigations"]["rfg"]["presence"] << "\n";
    os << "SafeSEH         : " << j["mitigations"]["safeSEH"]["presence"] << "\n";
    os << "GS              : " << j["mitigations"]["gs"]["presence"] << "\n";
    os << "Authenticode    : " << j["mitigations"]["authenticode"]["presence"] << "\n";
    os << ".NET            : " << j["mitigations"]["dotNET"]["presence"] << "\n";
    os << "CET Compatible  : " << j["mitigations"]["CetCompat"]["presence"] << "\n";
    return os;
}
}  // namespace checksec

void usage(char* argv[]) {
    std::cerr << "Syntax : " << argv[0] << " [--json] <file [file ...]>"
              << "\n";
    std::cerr << "Example: " << argv[0] << " --json doom2.exe"
              << "\n";
    std::cerr << "  -j/--json will output JSON to stdout"
              << "\n";
    std::cerr << "Exit codes: 0 = ok, 1 = usage error, 2 = unsigned input, "
                 "3 = invalid signature, 4 = unparsable input, 5 = general error"
              << "\n";
    std::cerr << "With multiple inputs, the most severe per-input exit code is returned."
              << "\n";
}

void version() { std::cerr << "Winchecksec version " << WINCHECKSEC_VERSION << "\n"; }

int main(int argc, char* argv[]) {
    argh::parser cmdl(argc, argv);

    if (cmdl[{"-V", "--version"}]) {
        version();
        return ExitCode::Ok;
    }

    bool jsonOutput = cmdl[{"-j", "--json"}];
    if (cmdl.size() < 2) {
        usage(argv);
        return ExitCode::UsageError;
    }

    const auto fileCount = std::distance(std::next(cmdl.begin()), cmdl.end());

    int worstExitCode = ExitCode::Ok;
    Summary summary;

    // TODO(ww): https://github.com/adishavit/argh/issues/57
    auto results = ordered_json::array();
    for (auto path = std::next(cmdl.begin()); path != cmdl.end(); ++path) {
        int fileExitCode = ExitCode::Ok;
        try {
            checksec::Checksec csec(*path);

            switch (csec.authenticodeState()) {
                case checksec::AuthenticodeState::Valid:
                    summary.ok += 1;
                    break;
                case checksec::AuthenticodeState::NotSigned:
                    summary.unsigned_ += 1;
                    fileExitCode = ExitCode::Unsigned;
                    break;
                case checksec::AuthenticodeState::Invalid:
                    summary.invalidSignature += 1;
                    fileExitCode = ExitCode::InvalidSignature;
                    break;
            }

            if (jsonOutput) {
                results.push_back(csec);
            } else {
                std::cout << "Results for: " << *path << '\n';
                std::cout << csec << '\n';
            }
        } catch (checksec::ChecksecError& error) {
            summary.failed += 1;
            fileExitCode = ExitCode::ParseError;
            if (jsonOutput) {
                results.push_back(ordered_json{
                    {"path", *path},
                    {"error", error.what()},
                });
            } else {
                std::cerr << *path << ": " << error.what() << '\n';
            }
        } catch (...) {
            summary.failed += 1;
            fileExitCode = ExitCode::GeneralError;
            if (jsonOutput) {
                results.push_back(ordered_json{
                    {"path", *path},
                    {"error", "General error"},
                });
            } else {
                std::cerr << *path << ": General error" << '\n';
            }
        }

        worstExitCode = std::max(worstExitCode, fileExitCode);
    }

    if (jsonOutput) {
        std::cout << ordered_json{
            {"results", results},
            {"summary", summary},
        } << '\n';
    } else if (fileCount > 1) {
        std::cout << summary << '\n';
    }

    return worstExitCode;
}
