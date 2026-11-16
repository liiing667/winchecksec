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

TEST(Winchecksec, UnparsableInput) {
    // A non-PE input must raise ChecksecError, making parse failures
    // distinguishable from (un)signed states.
    auto *path = WINCHECKSEC_TEST_ASSETS "/not-a-pe.txt";

    EXPECT_THROW(
        {
            checksec::Checksec checksec(path);
            (void)checksec;
        },
        checksec::ChecksecError);
}

TEST(Winchecksec, AuthenticodeUnsigned) {
    for (auto *path : {WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe",
                       WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe"}) {
        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.authenticodeState(), checksec::AuthenticodeState::NotSigned);
        EXPECT_FALSE(checksec.isAuthenticode());
        EXPECT_TRUE(checksec.isAuthenticode().explanation.has_value());
    }
}

TEST(Winchecksec, AuthenticodeValid) {
    for (auto *path : {WINCHECKSEC_TEST_ASSETS "/32/pegoat-authenticode.exe",
                       WINCHECKSEC_TEST_ASSETS "/64/pegoat-authenticode.exe"}) {
        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.authenticodeState(), checksec::AuthenticodeState::Valid);
        EXPECT_TRUE(checksec.isAuthenticode());
    }
}

TEST(Winchecksec, AuthenticodeTampered) {
    // These binaries have valid signatures over their original contents, but
    // were modified afterwards: the signature must not verify.
    for (auto *path : {WINCHECKSEC_TEST_ASSETS "/32/pegoat-authenticode-tampered.exe",
                       WINCHECKSEC_TEST_ASSETS "/64/pegoat-authenticode-tampered.exe"}) {
        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.authenticodeState(), checksec::AuthenticodeState::Invalid);
        EXPECT_FALSE(checksec.isAuthenticode());
    }
}

TEST(Winchecksec, AuthenticodeMissingIntermediate) {
    // These binaries are signed with a leaf certificate whose issuing
    // intermediate CA certificate is not embedded in the signature. The
    // checksum and PKCS#7 signature verify, but the incomplete chain must
    // not be reported as validly signed.
    for (auto *path :
         {WINCHECKSEC_TEST_ASSETS "/32/pegoat-authenticode-missing-intermediate.exe",
          WINCHECKSEC_TEST_ASSETS "/64/pegoat-authenticode-missing-intermediate.exe"}) {
        auto checksec = checksec::Checksec(path);

        EXPECT_EQ(checksec.authenticodeState(), checksec::AuthenticodeState::Invalid);
        EXPECT_FALSE(checksec.isAuthenticode());
        EXPECT_NE(checksec.isAuthenticode().explanation.value_or("").find("chain"),
                  std::string::npos);
    }
}
