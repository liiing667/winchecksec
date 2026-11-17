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

TEST(Winchecksec, SafeSEHNotApplicable64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_EQ(checksec.isSafeSEH().presence, checksec::MitigationPresence::NotApplicable);
}

TEST(Winchecksec, SafeSEHNotPresent32) {
    // The stock pegoat load config directory is too short to carry the
    // SafeSEH fields, so the check stays NotPresent.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.isSafeSEH().presence, checksec::MitigationPresence::NotPresent);
    }

    // An empty handler table/count means SafeSEH is not in effect.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-no-safeseh.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.isSafeSEH().presence, checksec::MitigationPresence::NotPresent);
    }
}

TEST(Winchecksec, SafeSEHPresent32) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-safeseh-valid.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_EQ(checksec.isSafeSEH().presence, checksec::MitigationPresence::Present);
    EXPECT_TRUE(checksec.isSafeSEH());
}

TEST(Winchecksec, SafeSEHUnknown32) {
    // A non-zero table pointer with a zero count is malformed.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-safeseh-inconsistent.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.isSafeSEH().presence, checksec::MitigationPresence::Unknown);
        EXPECT_FALSE(checksec.isSafeSEH());
        EXPECT_TRUE(checksec.isSafeSEH().explanation.has_value());
    }

    // A handler table that straddles a section boundary cannot be read as one
    // contiguous table, so presence cannot be proven.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-safeseh-cross-section.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.isSafeSEH().presence, checksec::MitigationPresence::Unknown);
        EXPECT_FALSE(checksec.isSafeSEH());
        EXPECT_TRUE(checksec.isSafeSEH().explanation.has_value());
    }

    // A handler table whose entries run past the file buffer is truncated.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-safeseh-truncated.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.isSafeSEH().presence, checksec::MitigationPresence::Unknown);
        EXPECT_FALSE(checksec.isSafeSEH());
        EXPECT_TRUE(checksec.isSafeSEH().explanation.has_value());
    }
}

TEST(Winchecksec, CetCompat64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-cetcompat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_TRUE(checksec.isCetCompat());
}
