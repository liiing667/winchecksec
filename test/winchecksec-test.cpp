#include "gtest/gtest.h"

#include <checksec.h>

TEST(Winchecksec, NoDynamicBase32) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-no-dynamicbase.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isDynamicBase());
    EXPECT_FALSE(checksec.isASLR());
}

TEST(Winchecksec, NoDynamicBase64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-dynamicbase.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isDynamicBase());
    EXPECT_FALSE(checksec.isASLR());
}

TEST(Winchecksec, NoHighEntropyVA32) {
    // NOTE: 32-bit programs obviously don't support 64-bit ASLR.
    auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isHighEntropyVA());
    EXPECT_TRUE(checksec.isASLR());
}

TEST(Winchecksec, HighEntropyVA64) {
    // By default, 64-bit PEs use their full address space for ASLR.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isHighEntropyVA());
        EXPECT_TRUE(checksec.isASLR());
    }

    // ...but it can be disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-highentropyva.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isHighEntropyVA());
        EXPECT_TRUE(checksec.isASLR());
    }
}

TEST(Winchecksec, NX32) {
    // By default, modern PEs support NX/DEP.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isNX());
    }

    // ...but it can be disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-no-nxcompat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isNX());
    }
}

TEST(Winchecksec, NX64) {
    // By default, modern PEs support NX/DEP.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isNX());
    }

    // ...but it can be disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-nxcompat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isNX());
    }
}

TEST(Winchecksec, CFG32) {
    // By default, modern PEs do not support CFG.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }

    // ...but it can be enabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-yes-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isCFG());
    }

    // ...or explicitly disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-no-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }
}

TEST(Winchecksec, CFG64) {
    // By default, modern PEs do not support CFG.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }

    // ...but it can be enabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-yes-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isCFG());
    }

    // ...or explicitly disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }
}

TEST(Winchecksec, NoCetCompat64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-cetcompat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isCetCompat());
}

TEST(Winchecksec, CetCompat64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-cetcompat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_TRUE(checksec.isCetCompat());
}

TEST(Winchecksec, CetCompat32) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-cetcompat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_TRUE(checksec.isCetCompat());
}

TEST(Winchecksec, NoCetCompat32) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isCetCompat());
}

// A malformed EX_DLLCHARACTERISTICS debug directory must never be reported as
// Present or as a normal, clean absence. Each of these binaries contains a
// type-20 debug directory whose payload cannot be read within the file's
// bounds (or whose declared SizeOfData is too small), so CetCompat must be
// reported as NotImplemented for both the 32- and 64-bit parse paths.
TEST(Winchecksec, MalformedCetCompat64) {
    const char *paths[] = {
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat64-cetcompat-at-eof.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat64-cetcompat-oob.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat64-cetcompat-wrap.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat64-cetcompat-forge-present.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat64-cetcompat-sizeofdata-one.exe",
    };

    for (auto *path : paths) {
        auto image = checksec::Checksec(path);

        auto report = image.isCetCompat();
        EXPECT_EQ(report.presence, checksec::MitigationPresence::NotImplemented) << path;
        EXPECT_NE(report.presence, checksec::MitigationPresence::Present) << path;
    }
}

TEST(Winchecksec, MalformedCetCompat32) {
    const char *paths[] = {
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat32-cetcompat-at-eof.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat32-cetcompat-oob.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat32-cetcompat-wrap.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat32-cetcompat-forge-present.exe",
        WINCHECKSEC_TEST_ASSETS "/malformed/pegoat32-cetcompat-sizeofdata-one.exe",
    };

    for (auto *path : paths) {
        auto image = checksec::Checksec(path);

        auto report = image.isCetCompat();
        EXPECT_EQ(report.presence, checksec::MitigationPresence::NotImplemented) << path;
        EXPECT_NE(report.presence, checksec::MitigationPresence::Present) << path;
    }
}

TEST(Winchecksec, InvalidFileRaises) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/malformed/does-not-exist.exe";

    EXPECT_THROW(checksec::Checksec image(path), checksec::ChecksecError);
}
