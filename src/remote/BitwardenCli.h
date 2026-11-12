/*
 * Copyright (C) 2026 KeePassXC-Bitwarden contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef KEEPASSXC_BITWARDENCLI_H
#define KEEPASSXC_BITWARDENCLI_H

#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QLockFile>
#include <QMutex>
#include <QProcessEnvironment>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <functional>
#include <optional>
#include <stdexcept>

class BitwardenCliError : public std::runtime_error
{
public:
    enum class Reason
    {
        Failed,
        AuthenticationRequired,
        TwoFactorRequired,
        Conflict
    };

    explicit BitwardenCliError(const QString& message, Reason reason = Reason::Failed);
    QString message() const;
    Reason reason() const noexcept;

private:
    Reason m_reason;
};

// Call on a worker thread. Each adapter holds its CLI profile exclusively.
class BitwardenCli
{
public:
    struct VaultSnapshot
    {
        QJsonArray folders;
        QJsonArray items;
    };

    BitwardenCli(const QString& executable, const QUrl& server, const QString& email);
    ~BitwardenCli();

    QString version();
    bool supportsFullEditing();
    // A missing result indicates an unsupported CLI or an unavailable local vault cache.
    std::optional<VaultSnapshot> openCachedVault(const QByteArray& masterPassword);
    VaultSnapshot readVault(bool synchronize, bool force = false, const std::function<bool()>& canceled = {});
    // True when a fresh login successfully refreshed the vault during this call.
    bool connect(const QByteArray& masterPassword,
                 const QString& totpCode,
                 const QString& clientId,
                 const QByteArray& clientSecret);
    void unlock(const QByteArray& masterPassword);
    void lock();
    void sync(bool force = true);
    QJsonArray listFolders();
    QJsonArray listItems();
    QJsonObject editItem(const QString& id, const QJsonObject& item, const QString& expectedRevision);
    QJsonObject createItem(const QJsonObject& item);

private:
    QByteArray run(const QStringList& arguments,
                   const QByteArray& input = {},
                   const QProcessEnvironment& secrets = {}) const;
    QString cliVersion();
    QJsonObject writeItem(const QStringList& arguments, const QJsonObject& item) const;
    QJsonObject profileStatus() const;
    void verifyProfile(const QString& server, const QString& email) const;
    void syncVault(bool force) const;
    QJsonObject unlockProfile(const QProcessEnvironment& secrets);
    QJsonObject saveSessionKey(QByteArray key);
    void adoptSessionKey(QByteArray key);
    void clearSessionKey();
    void ensureUnlocked() const;
    QJsonObject checkRevision(const QString& id, const QString& expectedRevision) const;

    QString m_executable;
    QString m_server;
    QString m_email;
    QString m_profileDir;
    QLockFile m_profileLock;
    QMutex m_mutex;
    QString m_cliVersion;
    QByteArray m_sessionKey;
};

#endif // KEEPASSXC_BITWARDENCLI_H
