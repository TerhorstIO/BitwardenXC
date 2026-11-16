/*
 * Copyright (C) 2026 BitwardenXC contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "remote/BitwardenFolderJournal.h"

#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"
#include "remote/BitwardenCli.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QObject>
#include <QSaveFile>
#include <QScopeGuard>

#include <botan/mem_ops.h>
#include <botan/pwdhash.h>

#include <algorithm>
#include <utility>

namespace
{
    const auto journalHeader = QByteArrayLiteral("BWXCFolderJournal\x01");
    constexpr auto saltSize = 32;
    constexpr auto nonceSize = 12;
    constexpr auto tagSize = 16;
    constexpr auto keySize = 32;
    constexpr auto maxJournalSize = 4 * 1024 * 1024;

    void erase(QByteArray& data)
    {
        if (!data.isEmpty()) {
            Botan::secure_scrub_memory(data.data(), static_cast<std::size_t>(data.size()));
            data.clear();
        }
    }

    BitwardenCliError readError()
    {
        return BitwardenCliError(
            QObject::tr("Could not read the encrypted Bitwarden folder changes. The local data was kept."));
    }

    BitwardenCliError writeError()
    {
        return BitwardenCliError(QObject::tr("Could not save the Bitwarden folder changes locally."));
    }
} // namespace

BitwardenFolderJournal::~BitwardenFolderJournal()
{
    lock();
}

QJsonArray BitwardenFolderJournal::unlock(const QString& path, const QByteArray& masterPassword)
{
    lock();
    if (path.isEmpty() || masterPassword.isEmpty()) {
        throw readError();
    }

    QFile file(path);
    QByteArray envelope;
    QByteArray salt;
    if (file.open(QIODevice::ReadOnly)) {
        envelope = file.read(maxJournalSize + 1);
        if (file.error() != QFileDevice::NoError || envelope.size() > maxJournalSize
            || envelope.size() < journalHeader.size() + saltSize + nonceSize + tagSize + 2
            || !envelope.startsWith(journalHeader)) {
            throw readError();
        }
        salt = envelope.mid(journalHeader.size(), saltSize);
    } else {
        const QFileInfo fileInfo(file);
        if (fileInfo.exists() || fileInfo.isSymLink()) {
            throw readError();
        }
        salt = randomGen()->randomArray(saltSize);
    }

    QByteArray key(keySize, '\0');
    const auto wipeKey = qScopeGuard([&key] { erase(key); });
    const auto profile = QFileInfo(QFileInfo(path).absolutePath()).fileName().toUtf8();
    const auto kdfSalt = journalHeader + salt + profile;
    try {
        auto kdf = Botan::PasswordHashFamily::create_or_throw("Argon2id")->from_params(64 * 1024, 3, 4);
        kdf->derive_key(reinterpret_cast<uint8_t*>(key.data()),
                        key.size(),
                        masterPassword.constData(),
                        masterPassword.size(),
                        reinterpret_cast<const uint8_t*>(kdfSalt.constData()),
                        kdfSalt.size());
    } catch (const std::exception&) {
        throw readError();
    }

    QJsonArray operations;
    if (!envelope.isEmpty()) {
        const auto nonceOffset = journalHeader.size() + saltSize;
        const auto nonce = envelope.mid(nonceOffset, nonceSize);
        auto data = envelope.mid(nonceOffset + nonceSize);
        const auto wipeData = qScopeGuard([&data] { erase(data); });
        SymmetricCipher cipher;
        if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Decrypt, key, nonce) || !cipher.finish(data)) {
            throw readError();
        }
        operations = QJsonDocument::fromJson(data).array();
        if (operations.isEmpty()
            || !std::all_of(operations.constBegin(), operations.constEnd(), [](const QJsonValue& value) {
                   return value.isObject();
               })) {
            throw readError();
        }
    }

    m_path = path;
    m_salt = std::move(salt);
    m_key = std::move(key);
    return operations;
}

void BitwardenFolderJournal::save(const QJsonArray& operations)
{
    if (m_key.isEmpty()) {
        throw writeError();
    }

    if (operations.isEmpty()) {
        QFile file(m_path);
        if (file.exists() && !file.remove()) {
            throw writeError();
        }
        return;
    }

    auto data = QJsonDocument(operations).toJson(QJsonDocument::Compact);
    const auto wipeData = qScopeGuard([&data] { erase(data); });
    if (data.size() > maxJournalSize - journalHeader.size() - saltSize - nonceSize - tagSize) {
        throw writeError();
    }

    const auto nonce = randomGen()->randomArray(nonceSize);
    SymmetricCipher cipher;
    if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Encrypt, m_key, nonce) || !cipher.finish(data)) {
        throw writeError();
    }

    const auto envelope = journalHeader + m_salt + nonce + data;
    QSaveFile file(m_path);
    if (!file.open(QIODevice::WriteOnly) || file.write(envelope) != envelope.size() || !file.commit()) {
        throw writeError();
    }
}

void BitwardenFolderJournal::lock()
{
    erase(m_key);
    m_salt.clear();
    m_path.clear();
}
