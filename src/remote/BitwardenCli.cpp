/*
 * Copyright (C) 2026 KeePassXC-Bitwarden contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "BitwardenCli.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDeadlineTimer>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QJsonDocument>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QScopeGuard>
#include <QSet>
#include <QStandardPaths>
#include <QUuid>

#include <algorithm>
#include <utility>

namespace
{
    const auto defaultServer = QStringLiteral("https://bitwarden.com");
    const auto passwordVariable = QStringLiteral("KEEPASSXC_BITWARDEN_PASSWORD");
    const auto sessionVariable = QStringLiteral("BW_SESSION");
    const auto upstreamVersion = QStringLiteral("2026.10.1");
    const auto fullEditingVersion = QStringLiteral("2026.10.1-bitwardenxc.1");
    const auto cachedOpenVersion = QStringLiteral("2026.10.1-bitwardenxc.2");
    const auto organizationCacheVersion = QStringLiteral("2026.10.1-bitwardenxc.3");
    const auto organizationWritesVersion = QStringLiteral("2026.10.1-bitwardenxc.4");
    const auto nameKey = QStringLiteral("name");
    const auto notesKey = QStringLiteral("notes");
    const auto idKey = QStringLiteral("id");
    const auto loginKey = QStringLiteral("login");
    const auto urisKey = QStringLiteral("uris");
    const auto uriKey = QStringLiteral("uri");
    const auto matchKey = QStringLiteral("match");
    const auto fieldsKey = QStringLiteral("fields");
    const auto folderIdKey = QStringLiteral("folderId");
    const auto organizationIdKey = QStringLiteral("organizationId");
    const auto collectionIdsKey = QStringLiteral("collectionIds");
    const auto canWriteItemsKey = QStringLiteral("canWriteItems");
    const auto canRenameKey = QStringLiteral("canRename");
    const QStringList loginTextKeys{QStringLiteral("username"), QStringLiteral("password"), QStringLiteral("totp")};
    constexpr int commandTimeoutMs = 60000;
    constexpr qsizetype outputLimit = 64 * 1024 * 1024;
    constexpr qsizetype diagnosticsLimit = 256 * 1024;

    QDateTime lastSync(const QJsonObject& status)
    {
        return QDateTime::fromString(status.value(QStringLiteral("lastSync")).toString(), Qt::ISODateWithMs);
    }

    bool supportsFullEditingVersion(const QString& version)
    {
        return version == fullEditingVersion || version == cachedOpenVersion || version == organizationCacheVersion
            || version == organizationWritesVersion;
    }

    QString executablePath(const QString& path)
    {
        const QFileInfo info(path);
        const auto canonicalPath = info.canonicalFilePath();
        if (!info.isAbsolute() || !info.isFile() || !info.isExecutable() || canonicalPath.isEmpty()) {
            throw BitwardenCliError(QStringLiteral("Wähle die Bitwarden-CLI über einen absoluten Dateipfad aus."));
        }
#ifdef Q_OS_WIN
        if (QFileInfo(canonicalPath).suffix().compare(QStringLiteral("exe"), Qt::CaseInsensitive) != 0) {
            throw BitwardenCliError(QStringLiteral("Wähle eine ausführbare Bitwarden-CLI-Datei (.exe) aus."));
        }
#endif
        return canonicalPath;
    }

    QString serverAddress(const QUrl& server)
    {
        if (!server.isValid() || server.scheme() != QStringLiteral("https") || server.host().isEmpty()
            || server.authority().contains(QLatin1Char('@')) || server.hasQuery() || server.hasFragment()) {
            throw BitwardenCliError(QStringLiteral("Gib eine HTTPS-Serveradresse ohne Zugangsdaten ein."));
        }

        auto normalized = server.adjusted(QUrl::NormalizePathSegments | QUrl::StripTrailingSlash);
        if (normalized.port() == 443) {
            normalized.setPort(-1);
        }
        const auto address = normalized.toString(QUrl::FullyEncoded);
        if (address == QStringLiteral("https://vault.bitwarden.com")) {
            return defaultServer;
        }
        if (address == QStringLiteral("https://bitwarden.eu")) {
            return QStringLiteral("https://vault.bitwarden.eu");
        }
        return address;
    }

    QString accountEmail(const QString& address)
    {
        const auto email = address.trimmed();
        static const QRegularExpression pattern(QStringLiteral(R"(^[^\s@]+@[^\s@]+$)"));
        if (email.startsWith(QLatin1Char('-')) || email.size() > 254 || email.contains(QChar::Null)
            || !pattern.match(email).hasMatch()) {
            throw BitwardenCliError(QStringLiteral("Gib eine gültige E-Mail-Adresse ein."));
        }
        return email;
    }

    QString profilePath(const QString& server, const QString& email)
    {
        const auto base = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
        if (base.isEmpty()) {
            throw BitwardenCliError(QStringLiteral("Das lokale Profilverzeichnis ist nicht verfügbar."));
        }

        const auto identity = server.toUtf8() + '\n' + email.toCaseFolded().toUtf8();
        const auto hash = QString::fromLatin1(QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex());
        return QDir(base).filePath(QStringLiteral("KeePassXC-Bitwarden/cli/") + hash);
    }

    void validatePassword(const QByteArray& password)
    {
        if (password.isEmpty() || password.contains('\0')) {
            throw BitwardenCliError(QStringLiteral("Gib dein Master-Passwort ein."));
        }
    }

    QProcessEnvironment passwordEnvironment(const QByteArray& password)
    {
        validatePassword(password);
        QProcessEnvironment result;
        result.insert(passwordVariable, QString::fromUtf8(password));
        return result;
    }

    bool validId(const QString& id)
    {
        const QUuid uuid(id);
        return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces).compare(id, Qt::CaseInsensitive) == 0;
    }

    QString itemId(const QString& id)
    {
        if (!validId(id)) {
            throw BitwardenCliError(QStringLiteral("Die Kennung des Tresoreintrags ist ungültig."));
        }
        return id.toLower();
    }

    bool validFolderLeaf(const QString& name)
    {
        return !name.isEmpty() && name.trimmed() == name && !name.contains(QChar::Null)
               && !name.contains(QLatin1Char('\r')) && !name.contains(QLatin1Char('\n'));
    }

    QString folderParentPath(const QString& path, const QUuid& parentId)
    {
        const auto separator = path.lastIndexOf(QLatin1Char('/'));
        if (!validFolderLeaf(path.mid(separator + 1)) || path.contains(QChar::Null)
            || (parentId.isNull() ? separator != -1 : separator <= 0)) {
            throw BitwardenCliError(QStringLiteral("Der Bitwarden-Ordnerpfad ist ungültig."));
        }
        return separator == -1 ? QString{} : path.left(separator);
    }

    QString uuidString(const QUuid& id)
    {
        return id.toString(QUuid::WithoutBraces);
    }

    std::optional<QSet<QUuid>> idSet(const QJsonValue& value)
    {
        if (!value.isArray()) {
            return std::nullopt;
        }
        QSet<QUuid> ids;
        for (const auto& entry : value.toArray()) {
            const auto idString = entry.toString();
            const QUuid id(idString);
            if (!validId(idString) || ids.contains(id)) {
                return std::nullopt;
            }
            ids.insert(id);
        }
        return ids;
    }

    bool validAccessList(const QJsonValue& value)
    {
        if (!value.isArray()) {
            return false;
        }
        QSet<QUuid> ids;
        for (const auto& entry : value.toArray()) {
            const auto access = entry.toObject();
            const auto idString = access.value(idKey).toString();
            const QUuid id(idString);
            if (!validId(idString) || ids.contains(id) || !access.value(QStringLiteral("readOnly")).isBool()
                || !access.value(QStringLiteral("hidePasswords")).isBool()
                || !access.value(QStringLiteral("manage")).isBool()) {
                return false;
            }
            ids.insert(id);
        }
        return true;
    }

    struct FolderIndex
    {
        explicit FolderIndex(const QJsonArray& folders, const QUuid& organizationId = {})
        {
            for (const auto& value : folders) {
                const auto folder = value.toObject();
                if (!organizationId.isNull() && folder.value(organizationIdKey) != uuidString(organizationId)) {
                    continue;
                }
                const auto idString = folder.value(idKey).toString();
                if (!validId(idString)) {
                    continue;
                }
                const QUuid id(idString);
                if (byId.contains(id)) {
                    throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat doppelte Ordnerkennungen geliefert."));
                }
                byId.insert(id, folder);
                byPath.insert(folder.value(nameKey).toString(), id);
            }
        }

        void verifyParent(const QUuid& id, const QString& path) const
        {
            if (!id.isNull() && (byId.value(id).value(nameKey) != path || byPath.count(path) != 1)) {
                throw BitwardenCliError(
                    QStringLiteral("Der übergeordnete Bitwarden-Ordner wurde geändert. Synchronisiere den Tresor und versuche es erneut."),
                    BitwardenCliError::Reason::Conflict);
            }
        }

        QHash<QUuid, QJsonObject> byId;
        QMultiHash<QString, QUuid> byPath;
    };

    QJsonDocument parseJson(QByteArray bytes)
    {
        const auto erase = qScopeGuard([&bytes] { bytes.fill('\0'); });
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(bytes, &error);
        if (error.error != QJsonParseError::NoError) {
            throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat ungültige Daten zurückgegeben."));
        }
        return document;
    }

    QJsonObject parseObject(QByteArray bytes)
    {
        const auto document = parseJson(std::move(bytes));
        if (!document.isObject()) {
            throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat kein JSON-Objekt zurückgegeben."));
        }
        return document.object();
    }

    QJsonArray parseArray(QByteArray bytes)
    {
        const auto document = parseJson(std::move(bytes));
        if (!document.isArray()) {
            throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat keine JSON-Liste zurückgegeben."));
        }
        return document.array();
    }

    QByteArray encodeJson(const QJsonDocument& document)
    {
        auto json = document.toJson(QJsonDocument::Compact);
        const auto erase = qScopeGuard([&json] { json.fill('\0'); });
        return json.toBase64();
    }

    bool hasValue(const QJsonValue& value)
    {
        return !value.isNull() && !value.isUndefined();
    }

    bool optionalString(const QJsonValue& value)
    {
        return !hasValue(value) || value.isString();
    }

    bool validUris(const QJsonValue& value)
    {
        const auto uris = value.toArray();
        return value.isArray() && std::all_of(uris.constBegin(), uris.constEnd(), [](const QJsonValue& entry) {
            const auto uri = entry.toObject();
            const auto match = uri.value(matchKey);
            const auto matchType = match.toInt(-1);
            return entry.isObject() && optionalString(uri.value(uriKey))
                   && (!hasValue(match) || (matchType >= 0 && matchType <= 5));
        });
    }

    bool validLogin(const QJsonValue& value)
    {
        if (!value.isObject()) {
            return false;
        }
        const auto login = value.toObject();
        for (auto field = login.constBegin(); field != login.constEnd(); ++field) {
            if (field.key() == urisKey) {
                if (!validUris(field.value())) {
                    return false;
                }
            } else if (!loginTextKeys.contains(field.key()) || !optionalString(field.value())) {
                return false;
            }
        }
        return true;
    }

    bool validFields(const QJsonValue& value)
    {
        const auto fields = value.toArray();
        return value.isArray() && std::all_of(fields.constBegin(), fields.constEnd(), [](const QJsonValue& entry) {
            const auto field = entry.toObject();
            const auto type = field.value(QStringLiteral("type")).toInt(-1);
            const auto linkedId = field.value(QStringLiteral("linkedId"));
            return entry.isObject() && type >= 0 && type <= 3 && optionalString(field.value(nameKey))
                   && optionalString(field.value(QStringLiteral("value")))
                   && (!hasValue(linkedId) || linkedId.toInt(-1) >= 0);
        });
    }

    bool validItemField(const QString& key, const QJsonValue& value, bool fullEditing)
    {
        if (key == nameKey) {
            return value.isString();
        }
        if (key == notesKey) {
            return optionalString(value);
        }
        if (!fullEditing) {
            return false;
        }
        if (key == loginKey) {
            return validLogin(value);
        }
        if (key == fieldsKey) {
            return validFields(value);
        }
        return key == folderIdKey && (value.isNull() || validId(value.toString()));
    }

    QJsonObject loginForWrite(const QJsonObject& changes, const QJsonObject& current = {})
    {
        QJsonObject login;
        for (const auto& key : loginTextKeys) {
            const auto value = changes.contains(key) ? changes.value(key) : current.value(key);
            if (!optionalString(value)) {
                throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat ungültige Login-Felder geliefert."));
            }
            login.insert(key, hasValue(value) ? value : QJsonValue::Null);
        }
        if (changes.contains(urisKey)) {
            // The SDK regenerates URI checksums. Only the URI and its match setting belong in this request.
            QJsonArray uris;
            for (const auto& entry : changes.value(urisKey).toArray()) {
                const auto uri = entry.toObject();
                QJsonObject updated;
                for (const auto& key : {uriKey, matchKey}) {
                    if (uri.contains(key)) {
                        updated.insert(key, uri.value(key));
                    }
                }
                uris.append(updated);
            }
            login.insert(urisKey, uris);
        }
        // The patched CLI reuses the native LoginView, including passkeys and other untouched fields.
        return login;
    }

    [[noreturn]] void commandFailed(const QByteArray& diagnostics)
    {
        using Reason = BitwardenCliError::Reason;
        if (diagnostics.contains("New device verification") || diagnostics.contains("authentication challenge")) {
            throw BitwardenCliError(QStringLiteral("Bitwarden verlangt eine zusätzliche Gerätebestätigung."),
                                   Reason::AuthenticationRequired);
        }
        if (diagnostics.contains("Code is required.") || diagnostics.contains("No provider selected.")) {
            throw BitwardenCliError(
                QStringLiteral("Bitwarden verlangt einen Bestätigungscode. Gib den Code aus deiner Authenticator-App ein."),
                Reason::TwoFactorRequired);
        }
        if (diagnostics.contains("password is incorrect") || diagnostics.contains("Invalid master password")) {
            throw BitwardenCliError(QStringLiteral("Die Anmeldung konnte mit diesem Passwort nicht bestätigt werden."),
                                   Reason::AuthenticationRequired);
        }
        if (diagnostics.contains("You are not logged in.") || diagnostics.contains("Vault is locked.")) {
            throw BitwardenCliError(QStringLiteral("Entsperre den Tresor oder melde dich erneut an."),
                                   Reason::AuthenticationRequired);
        }
        if (diagnostics.contains("out of date") || diagnostics.contains("resync the client")) {
            throw BitwardenCliError(QStringLiteral("Der Eintrag wurde auf einem anderen Gerät geändert."), Reason::Conflict);
        }
        throw BitwardenCliError(
            QStringLiteral("Die Bitwarden-CLI konnte die Aktion nicht ausführen. Prüfe die Verbindung und deine Berechtigung."));
    }
} // namespace

BitwardenCliError::BitwardenCliError(const QString& message, Reason reason)
    : std::runtime_error(message.toUtf8().constData())
    , m_reason(reason)
{
}

QString BitwardenCliError::message() const
{
    return QString::fromUtf8(what());
}

BitwardenCliError::Reason BitwardenCliError::reason() const noexcept
{
    return m_reason;
}

BitwardenCli::BitwardenCli(const QString& executable, const QUrl& server, const QString& email)
    : m_executable(executablePath(executable))
    , m_server(serverAddress(server))
    , m_email(accountEmail(email))
    , m_profileDir(profilePath(m_server, m_email))
    , m_profileLock(QDir(m_profileDir).filePath(QStringLiteral("profile.lock")))
{
    if (!QDir().mkpath(m_profileDir)) {
        throw BitwardenCliError(QStringLiteral("Das lokale Bitwarden-Profil konnte nicht angelegt werden."));
    }
    m_profileLock.setStaleLockTime(0);
    if (!m_profileLock.tryLock()) {
        throw BitwardenCliError(QStringLiteral("Das Bitwarden-Profil ist bereits in einem anderen Fenster geöffnet."));
    }
}

BitwardenCli::~BitwardenCli()
{
    clearSessionKey();
}

QString BitwardenCli::version()
{
    const QMutexLocker locker(&m_mutex);
    return cliVersion();
}

bool BitwardenCli::supportsFullEditing()
{
    const QMutexLocker locker(&m_mutex);
    return supportsFullEditingVersion(cliVersion());
}

std::optional<BitwardenCli::VaultSnapshot> BitwardenCli::openCachedVault(const QByteArray& masterPassword)
{
    const QMutexLocker locker(&m_mutex);
    const auto version = cliVersion();
    const bool supportsOrganizationCache = version == organizationCacheVersion || version == organizationWritesVersion;
    if (version != cachedOpenVersion && !supportsOrganizationCache) {
        return std::nullopt;
    }
    if (!m_sessionKey.isEmpty()) {
        throw BitwardenCliError(QStringLiteral("Der Bitwarden-Tresor ist bereits entsperrt."));
    }
    validatePassword(masterPassword);

    auto password = QString::fromUtf8(masterPassword);
    const auto wipePassword = qScopeGuard([&password] { password.fill(QChar()); });
    auto request = QJsonDocument(QJsonObject{{QStringLiteral("serverUrl"), m_server},
                                            {QStringLiteral("email"), m_email},
                                            {QStringLiteral("password"), password}})
                       .toJson(QJsonDocument::Compact);
    password.fill(QChar());
    const auto wipeRequest = qScopeGuard([&request] { request.fill('\0'); });
    const auto result = parseObject(run({QStringLiteral("bitwardenxc-open-cache")}, request));
    const auto kind = result.value(QStringLiteral("kind")).toString();
    if (kind == QStringLiteral("unavailable") && result.size() == 1) {
        return std::nullopt;
    }
    if (kind == QStringLiteral("unlockFailed") && result.size() == 1) {
        throw BitwardenCliError(QStringLiteral("Der Bitwarden-Tresor konnte nicht entsperrt werden. Prüfe dein Master-Passwort."),
                               BitwardenCliError::Reason::AuthenticationRequired);
    }

    const auto server = result.value(QStringLiteral("serverUrl")).toString();
    const auto email = result.value(QStringLiteral("email")).toString();
    const auto key = result.value(QStringLiteral("sessionKey"));
    const auto folders = result.value(QStringLiteral("folders"));
    const auto items = result.value(QStringLiteral("items"));
    const auto organizations = result.value(QStringLiteral("organizations"));
    const auto collections = result.value(QStringLiteral("collections"));
    if (kind != QStringLiteral("opened") || result.size() != (supportsOrganizationCache ? 8 : 6) || server.isEmpty()
        || email.isEmpty() || !key.isString() || !folders.isArray() || !items.isArray()
        || (supportsOrganizationCache && (!organizations.isArray() || !collections.isArray()))) {
        throw BitwardenCliError(QStringLiteral("Die BitwardenXC-CLI hat ungültige Tresordaten geliefert."));
    }
    verifyProfile(server, email);
    VaultSnapshot snapshot{folders.toArray(), items.toArray(), organizations.toArray(), collections.toArray()};
    const auto isObject = [](const QJsonValue& value) { return value.isObject(); };
    if (!std::all_of(snapshot.folders.constBegin(), snapshot.folders.constEnd(), isObject)
        || !std::all_of(snapshot.items.constBegin(), snapshot.items.constEnd(), isObject)
        || !std::all_of(snapshot.organizations.constBegin(), snapshot.organizations.constEnd(), isObject)
        || !std::all_of(snapshot.collections.constBegin(), snapshot.collections.constEnd(), isObject)) {
        throw BitwardenCliError(QStringLiteral("Die BitwardenXC-CLI hat ungültige Tresordaten geliefert."));
    }
    adoptSessionKey(key.toString().toLatin1());
    return snapshot;
}

QString BitwardenCli::cliVersion()
{
    if (!m_cliVersion.isEmpty()) {
        return m_cliVersion;
    }
    const auto output = QString::fromLatin1(run({QStringLiteral("--version")}).trimmed());
    static const QRegularExpression versionPattern(QStringLiteral(R"(^\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$)"));
    if (!versionPattern.match(output).hasMatch()) {
        throw BitwardenCliError(QStringLiteral("Die ausgewählte Datei meldet keine gültige CLI-Version."));
    }
    m_cliVersion = output;
    return m_cliVersion;
}

QJsonObject BitwardenCli::profileStatus() const
{
    const auto result = parseObject(run({QStringLiteral("status")}));
    const auto state = result.value(QStringLiteral("status")).toString();
    if (state == QStringLiteral("unauthenticated")) {
        return result;
    }
    if (state != QStringLiteral("locked") && state != QStringLiteral("unlocked")) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI meldet einen unbekannten Tresorstatus."));
    }
    verifyProfile(result.value(QStringLiteral("serverUrl")).toString(), result.value(QStringLiteral("userEmail")).toString());
    return result;
}

void BitwardenCli::verifyProfile(const QString& server, const QString& email) const
{
    const auto activeServer = server.isEmpty() ? defaultServer : serverAddress(QUrl(server));
    if (activeServer != m_server || email.compare(m_email, Qt::CaseInsensitive) != 0) {
        throw BitwardenCliError(QStringLiteral("Der angemeldete Bitwarden-Tresor passt nicht zum ausgewählten Profil."));
    }
}

bool BitwardenCli::connect(const QByteArray& masterPassword,
                           const QString& totpCode,
                           const QString& clientId,
                           const QByteArray& clientSecret)
{
    const QMutexLocker locker(&m_mutex);
    const auto passwordSecrets = passwordEnvironment(masterPassword);
    const bool useApiKey = !clientId.isEmpty();
    const auto id = clientId.trimmed();
    if (useApiKey) {
        static const QRegularExpression clientIdPattern(QStringLiteral(R"(^user\.[0-9a-fA-F-]{36}$)"));
        if (!clientIdPattern.match(id).hasMatch() || clientSecret.isEmpty() || clientSecret.contains('\0')) {
            throw BitwardenCliError(QStringLiteral("Gib die Client-ID und das Client Secret deines persönlichen API-Schlüssels ein."));
        }
    } else if (!totpCode.isEmpty()) {
        static const QRegularExpression otpPattern(QStringLiteral(R"(^[0-9]{6,8}$)"));
        if (!otpPattern.match(totpCode).hasMatch()) {
            throw BitwardenCliError(QStringLiteral("Gib den Zahlencode aus deiner Authenticator-App ein."));
        }
    }

    const auto previousStatus = profileStatus();
    const bool hasProfile = previousStatus.value(QStringLiteral("status")) != QStringLiteral("unauthenticated");
    if (hasProfile && !useApiKey && totpCode.isEmpty()) {
        unlockProfile(passwordSecrets);
        return false;
    }
    if (hasProfile) {
        const auto erase = qScopeGuard([this] { clearSessionKey(); });
        run({QStringLiteral("logout")});
    } else {
        clearSessionKey();
    }
    run({QStringLiteral("config"), QStringLiteral("server"), m_server});

    const auto loginStarted = QDateTime::currentDateTimeUtc();
    QJsonObject unlockedStatus;
    if (useApiKey) {
        QProcessEnvironment apiSecrets;
        apiSecrets.insert(QStringLiteral("BW_CLIENTID"), id);
        apiSecrets.insert(QStringLiteral("BW_CLIENTSECRET"), QString::fromUtf8(clientSecret));
        auto output = run({QStringLiteral("login"), QStringLiteral("--apikey")}, {}, apiSecrets);
        output.fill('\0');
        if (profileStatus().value(QStringLiteral("status")) != QStringLiteral("locked")) {
            throw BitwardenCliError(QStringLiteral("Die Anmeldung mit dem persönlichen API-Schlüssel konnte nicht bestätigt werden."),
                                   BitwardenCliError::Reason::AuthenticationRequired);
        }
        unlockedStatus = unlockProfile(passwordSecrets);
    } else {
        QStringList arguments{QStringLiteral("login"), m_email, QStringLiteral("--passwordenv"), passwordVariable};
        if (!totpCode.isEmpty()) {
            // The CLI takes noninteractive TOTP through --code. The master password stays in the child environment.
            arguments << QStringLiteral("--method") << QStringLiteral("0") << QStringLiteral("--code") << totpCode;
        }
        try {
            unlockedStatus = saveSessionKey(run(arguments, {}, passwordSecrets));
        } catch (const BitwardenCliError& error) {
            if (!totpCode.isEmpty() && error.reason() == BitwardenCliError::Reason::TwoFactorRequired) {
                throw BitwardenCliError(QStringLiteral("Bitwarden verlangt eine weitere Bestätigung, etwa per E-Mail."),
                                       BitwardenCliError::Reason::AuthenticationRequired);
            }
            throw;
        }
    }

    // These CLI versions force a full sync on login, but login can succeed even if that sync failed.
    const auto syncedAt = lastSync(unlockedStatus);
    const auto previousSync = lastSync(previousStatus);
    return (m_cliVersion == upstreamVersion || supportsFullEditingVersion(m_cliVersion)) && syncedAt.isValid()
           && syncedAt >= loginStarted && syncedAt <= QDateTime::currentDateTimeUtc()
           && (!previousSync.isValid() || syncedAt > previousSync);
}

void BitwardenCli::unlock(const QByteArray& masterPassword)
{
    const QMutexLocker locker(&m_mutex);
    const auto secrets = passwordEnvironment(masterPassword);
    if (profileStatus().value(QStringLiteral("status")) == QStringLiteral("unauthenticated")) {
        throw BitwardenCliError(QStringLiteral("Melde dich zuerst bei Bitwarden an."),
                               BitwardenCliError::Reason::AuthenticationRequired);
    }
    unlockProfile(secrets);
}

QJsonObject BitwardenCli::unlockProfile(const QProcessEnvironment& secrets)
{
    return saveSessionKey(run({QStringLiteral("unlock"), QStringLiteral("--passwordenv"), passwordVariable}, {}, secrets));
}

void BitwardenCli::lock()
{
    const QMutexLocker locker(&m_mutex);
    const auto erase = qScopeGuard([this] { clearSessionKey(); });
    if (!m_sessionKey.isEmpty()) {
        run({QStringLiteral("lock")});
    }
}

void BitwardenCli::sync(bool force)
{
    const QMutexLocker locker(&m_mutex);
    syncVault(force);
}

void BitwardenCli::syncVault(bool force) const
{
    QStringList arguments{QStringLiteral("sync")};
    if (force) {
        arguments.append(QStringLiteral("--force"));
    }
    run(arguments);
}

BitwardenCli::VaultSnapshot
BitwardenCli::readVault(bool synchronize, bool force, const std::function<bool()>& canceled)
{
    const QMutexLocker locker(&m_mutex);
    const auto checkCanceled = [&canceled] {
        if (canceled && canceled()) {
            throw BitwardenCliError(QStringLiteral("Der Bitwarden-Vorgang wurde abgebrochen."));
        }
    };
    checkCanceled();
    ensureUnlocked();
    if (synchronize) {
        syncVault(force);
        checkCanceled();
    }
    auto folders = parseArray(run({QStringLiteral("list"), QStringLiteral("folders")}));
    checkCanceled();
    auto items = parseArray(run({QStringLiteral("list"), QStringLiteral("items")}));
    checkCanceled();
    auto organizations = parseArray(run({QStringLiteral("list"), QStringLiteral("organizations")}));
    checkCanceled();
    QJsonArray collections;
    if (!organizations.isEmpty()) {
        // These are the local, accessible collections. "org-collections" uses an administrative API.
        collections = parseArray(run({QStringLiteral("list"), QStringLiteral("collections")}));
        checkCanceled();
    }
    return {std::move(folders), std::move(items), std::move(organizations), std::move(collections)};
}

QJsonObject BitwardenCli::editItem(const QString& id, const QJsonObject& item, const QString& expectedRevision)
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    const auto canonicalId = itemId(id);
    const bool fullEdit = item.contains(loginKey) || item.contains(fieldsKey) || item.contains(folderIdKey);
    if (fullEdit && !supportsFullEditingVersion(cliVersion())) {
        throw BitwardenCliError(QStringLiteral("Für diese Änderungen ist die BitwardenXC-CLI erforderlich."));
    }
    for (auto field = item.constBegin(); field != item.constEnd(); ++field) {
        if (field.key() == idKey && field.value() == canonicalId) {
            continue;
        }
        if (!validItemField(field.key(), field.value(), fullEdit)) {
            throw BitwardenCliError(QStringLiteral("Der persönliche Login enthält ungültige Änderungen."));
        }
    }
    if (!fullEdit && !item.contains(nameKey) && !item.contains(notesKey)) {
        throw BitwardenCliError(QStringLiteral("Für den Eintrag wurden keine Änderungen übergeben."));
    }

    const auto current = checkRevision(canonicalId, expectedRevision);
    const auto edit = current.value(QStringLiteral("edit"));
    const auto viewPassword = current.value(QStringLiteral("viewPassword"));
    if (current.value(QStringLiteral("type")).toInt() != 1 || !current.value(QStringLiteral("login")).isObject()
        || hasValue(current.value(QStringLiteral("organizationId"))) || hasValue(current.value(QStringLiteral("deletedDate")))
        || hasValue(current.value(QStringLiteral("archivedDate"))) || (hasValue(edit) && !edit.toBool())
        || (hasValue(viewPassword) && !viewPassword.toBool())) {
        throw BitwardenCliError(QStringLiteral("Dieser persönliche Login kann nicht bearbeitet werden."));
    }

    const auto folder = item.contains(folderIdKey) ? item.value(folderIdKey) : current.value(folderIdKey);
    const auto favorite = current.value(QStringLiteral("favorite"));
    const auto reprompt = current.value(QStringLiteral("reprompt"));
    const auto name = item.contains(nameKey) ? item.value(nameKey) : current.value(nameKey);
    const auto notes = item.contains(notesKey) ? item.value(notesKey) : current.value(notesKey);
    if (!name.isString() || !favorite.isBool() || (reprompt.toInt(-1) != 0 && reprompt.toInt(-1) != 1)
        || (hasValue(folder) && !folder.isString()) || (hasValue(notes) && !notes.isString())) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat unvollständige Eintragsdaten geliefert."));
    }

    // Omitted keys keep the existing login, fields and history on the server.
    QJsonObject updated{
        {QStringLiteral("type"), 1},
        {folderIdKey, hasValue(folder) ? folder : QJsonValue::Null},
        {QStringLiteral("favorite"), favorite},
        {QStringLiteral("reprompt"), reprompt},
        {nameKey, name},
        {notesKey, hasValue(notes) ? notes : QJsonValue::Null},
        {QStringLiteral("revisionDate"), expectedRevision},
    };
    if (item.contains(loginKey)) {
        updated.insert(loginKey, loginForWrite(item.value(loginKey).toObject(), current.value(loginKey).toObject()));
    }
    if (item.contains(fieldsKey)) {
        updated.insert(fieldsKey, item.value(fieldsKey));
    }
    const auto saved = writeObject({QStringLiteral("edit"), QStringLiteral("item"), canonicalId}, updated);
    if (saved.value(idKey) != canonicalId) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat die Änderung nicht bestätigt."));
    }
    return saved;
}

QJsonObject BitwardenCli::createItem(const QJsonObject& item)
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    const auto typeKey = QStringLiteral("type");
    const auto favoriteKey = QStringLiteral("favorite");
    const auto repromptKey = QStringLiteral("reprompt");
    const auto organization = item.value(organizationIdKey);
    const bool shared = hasValue(organization);
    const QUuid organizationId(organization.toString());
    const auto requestedCollections = idSet(item.value(collectionIdsKey));
    if (shared
        && (!validId(organization.toString()) || !requestedCollections || requestedCollections->isEmpty()
            || hasValue(item.value(folderIdKey)))) {
        throw BitwardenCliError(QStringLiteral("Ein Organisationslogin braucht eine gültige Sammlung."));
    }

    for (auto field = item.constBegin(); field != item.constEnd(); ++field) {
        const auto& key = field.key();
        const auto& value = field.value();
        if ((key == typeKey && value.toInt() == 1) || (key == favoriteKey && value.isBool())
            || (key == repromptKey && (value.toInt(-1) == 0 || value.toInt(-1) == 1))
            || (shared && (key == organizationIdKey || key == collectionIdsKey))
            || validItemField(key, value, true)) {
            continue;
        }
        throw BitwardenCliError(QStringLiteral("Der neue Login enthält ungültige Felder."));
    }
    if (item.value(nameKey).toString().trimmed().isEmpty() || !item.contains(loginKey)) {
        throw BitwardenCliError(QStringLiteral("Der neue Login benötigt einen Titel und Login-Daten."));
    }

    auto created = item;
    created.insert(typeKey, 1);
    created.insert(favoriteKey, item.value(favoriteKey).toBool());
    created.insert(repromptKey, item.value(repromptKey).toInt());
    created.insert(loginKey, loginForWrite(item.value(loginKey).toObject()));
    if (shared) {
        ensureOrganizationWrites();
        syncVault(true);
        const FolderIndex collections(listCollections(organizationId), organizationId);
        for (const auto& id : *requestedCollections) {
            if (!collections.byId.value(id).value(canWriteItemsKey).toBool()) {
                throw BitwardenCliError(QStringLiteral("Dein Konto darf keine Einträge in dieser Sammlung anlegen."));
            }
        }
    }
    const auto saved = writeObject({QStringLiteral("create"), QStringLiteral("item")}, created);
    if (!validId(saved.value(idKey).toString())
        || (shared && (saved.value(organizationIdKey) != uuidString(organizationId)
                       || idSet(saved.value(collectionIdsKey)) != requestedCollections))) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat den neuen Eintrag nicht bestätigt."));
    }
    return saved;
}

QJsonObject BitwardenCli::moveItem(const QString& id,
                                   const QString& expectedRevision,
                                   const QUuid& sourceOrganizationId,
                                   const QUuid& organizationId,
                                   const QUuid& fromCollection,
                                   const QUuid& toCollection)
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    ensureOrganizationWrites();
    const auto canonicalId = itemId(id);
    const bool transfer = sourceOrganizationId.isNull();
    if (organizationId.isNull() || toCollection.isNull() || (transfer && !fromCollection.isNull())
        || (!transfer && sourceOrganizationId != organizationId)) {
        throw BitwardenCliError(QStringLiteral("Dieser Eintrag kann nicht in die ausgewählte Sammlung verschoben werden."));
    }

    const auto current = checkRevision(canonicalId, expectedRevision);
    const auto owner = current.value(organizationIdKey);
    if ((transfer ? hasValue(owner) : owner != uuidString(sourceOrganizationId))
        || !current.value(QStringLiteral("edit")).toBool() || !current.value(QStringLiteral("viewPassword")).toBool()
        || current.value(QStringLiteral("reprompt")).toInt() != 0
        || hasValue(current.value(QStringLiteral("deletedDate")))
        || hasValue(current.value(QStringLiteral("archivedDate")))) {
        throw BitwardenCliError(QStringLiteral("Dein Konto darf diesen Eintrag nicht verschieben."));
    }

    const FolderIndex collections(listCollections(organizationId), organizationId);
    if (!collections.byId.value(toCollection).value(canWriteItemsKey).toBool()
        || (!fromCollection.isNull() && !collections.byId.value(fromCollection).value(canWriteItemsKey).toBool())) {
        throw BitwardenCliError(QStringLiteral("Dein Konto darf keine Einträge zwischen diesen Sammlungen verschieben."));
    }

    QJsonArray selected;
    QStringList args;
    if (transfer) {
        selected.append(uuidString(toCollection));
        // The official move command re-encrypts the existing cipher (including its key material) for the organization.
        args = {QStringLiteral("move"), canonicalId, uuidString(organizationId)};
    } else {
        const auto currentCollections = idSet(current.value(collectionIdsKey));
        if (!currentCollections || (!fromCollection.isNull() && !currentCollections->contains(fromCollection))) {
            throw BitwardenCliError(QStringLiteral("Die Sammlungszuordnung des Eintrags wurde geändert."),
                                   BitwardenCliError::Reason::Conflict);
        }
        if (currentCollections->contains(toCollection) && (fromCollection.isNull() || fromCollection == toCollection)) {
            return current;
        }
        for (const auto& existing : current.value(collectionIdsKey).toArray()) {
            if (QUuid(existing.toString()) != fromCollection) {
                selected.append(existing);
            }
        }
        if (!currentCollections->contains(toCollection)) {
            selected.append(uuidString(toCollection));
        }
        args = {QStringLiteral("edit"), QStringLiteral("item-collections"), canonicalId,
                QStringLiteral("--organizationid"), uuidString(organizationId)};
    }
    const auto result = writeArray(args, selected);
    if (result.value(idKey) != canonicalId || result.value(organizationIdKey) != uuidString(organizationId)
        || idSet(result.value(collectionIdsKey)) != idSet(selected)) {
        throw BitwardenCliError(QStringLiteral("Bitwarden hat die Sammlungszuordnung nicht bestätigt. Synchronisiere den Tresor."),
                               BitwardenCliError::Reason::WriteUncertain);
    }
    return result;
}

QString BitwardenCli::folderJournalPath() const
{
    return QDir(m_profileDir).filePath(QStringLiteral("pending-folders.v1"));
}

QJsonObject BitwardenCli::createFolder(const QUuid& parentId, const QString& path, bool recoverUncertain)
{
    return createFolderOrCollection({}, parentId, path, recoverUncertain);
}

QJsonObject BitwardenCli::createCollection(const QUuid& organizationId,
                                           const QUuid& parentId,
                                           const QString& path,
                                           bool recoverUncertain)
{
    if (organizationId.isNull()) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-Organisation fehlt."));
    }
    return createFolderOrCollection(organizationId, parentId, path, recoverUncertain);
}

QJsonObject BitwardenCli::createFolderOrCollection(const QUuid& organizationId,
                                                   const QUuid& parentId,
                                                   const QString& path,
                                                   bool recoverUncertain)
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    const auto parentPath = folderParentPath(path, parentId);
    const bool shared = !organizationId.isNull();
    if (shared) {
        ensureOrganizationWrites();
    }

    // Ordinary writes only need a vault update if the account revision changed.
    // Recovery checks the server even if a timed-out create failed to update the CLI cache.
    syncVault(recoverUncertain || shared);
    const FolderIndex folders(shared ? listCollections(organizationId)
                                    : parseArray(run({QStringLiteral("list"), QStringLiteral("folders")})),
                              organizationId);
    folders.verifyParent(parentId, parentPath);
    const auto existing = folders.byPath.values(path);
    if (!existing.isEmpty()) {
        if (recoverUncertain && existing.size() == 1) {
            return folders.byId.value(existing.first());
        }
        throw BitwardenCliError(QStringLiteral("Ein Bitwarden-Ordner mit diesem Pfad ist bereits vorhanden."),
                               BitwardenCliError::Reason::Conflict);
    }

    const auto uncertain = QStringLiteral("Bitwarden hat die Ordnererstellung nicht bestätigt. Synchronisiere den Tresor, bevor du es erneut versuchst.");
    QStringList arguments{QStringLiteral("create"), shared ? QStringLiteral("org-collection") : QStringLiteral("folder")};
    QJsonObject request{{nameKey, path}};
    if (shared) {
        const auto organization = uuidString(organizationId);
        const auto organizations = parseArray(run({QStringLiteral("list"), QStringLiteral("organizations")}));
        const auto canCreate = std::find_if(organizations.cbegin(), organizations.cend(), [&organization](const QJsonValue& row) {
            return row.toObject().value(idKey) == organization && row.toObject().value(QStringLiteral("canCreateCollections")).toBool();
        });
        if (canCreate == organizations.cend()) {
            throw BitwardenCliError(QStringLiteral("Dein Konto darf in dieser Organisation keine Sammlungen anlegen."));
        }
        arguments << QStringLiteral("--organizationid") << organization;
        request.insert(organizationIdKey, organization);
    }
    QJsonObject saved;
    try {
        saved = writeObject(arguments, request);
        const auto id = saved.value(idKey).toString();
        if (!validId(id) || folders.byId.contains(QUuid(id)) || saved.value(nameKey) != path
            || (shared && saved.value(organizationIdKey) != uuidString(organizationId))) {
            throw BitwardenCliError(uncertain);
        }
        if (shared) {
            // A new collection result includes access policy details instead of the display permissions.
            // Confirm the server-created row with the same permission flags as the next snapshot.
            syncVault(true);
            const FolderIndex refreshed(listCollections(organizationId), organizationId);
            saved = refreshed.byId.value(QUuid(id));
            if (saved.value(nameKey) != path) {
                throw BitwardenCliError(uncertain);
            }
        }
    } catch (const BitwardenCliError& error) {
        if (error.reason() != BitwardenCliError::Reason::Failed) {
            throw;
        }
        throw BitwardenCliError(uncertain, BitwardenCliError::Reason::WriteUncertain);
    }
    return saved;
}

QList<QJsonObject> BitwardenCli::editFolders(const QList<FolderEdit>& edits, const QUuid& destinationParentId)
{
    return editFoldersOrCollections({}, edits, destinationParentId);
}

QList<QJsonObject> BitwardenCli::editCollections(const QUuid& organizationId,
                                                 const QList<FolderEdit>& edits,
                                                 const QUuid& destinationParentId)
{
    if (organizationId.isNull()) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-Organisation fehlt."));
    }
    return editFoldersOrCollections(organizationId, edits, destinationParentId);
}

QList<QJsonObject> BitwardenCli::editFoldersOrCollections(const QUuid& organizationId,
                                                          const QList<FolderEdit>& edits,
                                                          const QUuid& destinationParentId)
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    if (edits.isEmpty()) {
        return {};
    }
    const bool shared = !organizationId.isNull();
    if (shared) {
        ensureOrganizationWrites();
    }

    const auto& first = edits.first();
    const auto parentPath = folderParentPath(first.newPath, destinationParentId);
    const auto oldPrefix = first.oldPath + QLatin1Char('/');
    const auto newPrefix = first.newPath + QLatin1Char('/');
    const auto invalid = QStringLiteral("Die Bitwarden-Ordneränderung ist ungültig.");
    if (first.oldPath.isEmpty() || first.newPath == first.oldPath || first.newPath.startsWith(oldPrefix)) {
        throw BitwardenCliError(invalid);
    }
    QSet<QUuid> ids;
    QSet<QString> oldPaths;
    for (const auto& edit : edits) {
        if (edit.id.isNull() || edit.id == destinationParentId || ids.contains(edit.id)
            || oldPaths.contains(edit.oldPath) || edit.newPath.contains(QChar::Null)
            || (edit.oldPath != first.oldPath && !edit.oldPath.startsWith(oldPrefix))
            || edit.newPath != first.newPath + edit.oldPath.mid(first.oldPath.size())) {
            throw BitwardenCliError(invalid);
        }
        ids.insert(edit.id);
        oldPaths.insert(edit.oldPath);
    }

    // A batch is a sequence of Bitwarden requests. A fresh preflight lets us resume a partially applied batch.
    syncVault(true);
    const FolderIndex folders(shared ? listCollections(organizationId)
                                    : parseArray(run({QStringLiteral("list"), QStringLiteral("folders")})),
                              organizationId);
    folders.verifyParent(destinationParentId, parentPath);
    const auto conflict =
        QStringLiteral("Ein Bitwarden-Ordner wurde auf einem anderen Gerät geändert. Synchronisiere den Tresor und prüfe die Ordner.");
    const bool singleEdit = edits.size() == 1;
    const auto originalIds = folders.byPath.values(first.oldPath);
    const bool sourceStillExists = singleEdit
        && std::any_of(originalIds.cbegin(), originalIds.cend(), [&first](const QUuid& id) { return id != first.id; });
    for (auto entry = folders.byPath.constBegin(); entry != folders.byPath.constEnd(); ++entry) {
        const auto& path = entry.key();
        if (!ids.contains(entry.value())
            && ((path.startsWith(oldPrefix) && !sourceStillExists) || path.startsWith(newPrefix))) {
            throw BitwardenCliError(conflict, BitwardenCliError::Reason::Conflict);
        }
    }
    for (const auto& edit : edits) {
        const auto row = folders.byId.value(edit.id);
        const auto current = row.value(nameKey);
        if (!current.isString() || (current != edit.oldPath && current != edit.newPath)
            || (folders.byPath.count(current.toString()) != 1 && !(sourceStillExists && current == edit.oldPath))
            || (!singleEdit && current == edit.newPath && folders.byPath.contains(edit.oldPath))) {
            throw BitwardenCliError(conflict, BitwardenCliError::Reason::Conflict);
        }
        if (current == edit.oldPath && folders.byPath.contains(edit.newPath)) {
            throw BitwardenCliError(QStringLiteral("Ein Bitwarden-Ordner mit diesem Pfad ist bereits vorhanden."),
                                   BitwardenCliError::Reason::Conflict);
        }
        if (shared && current == edit.oldPath && !row.value(canRenameKey).toBool()) {
            throw BitwardenCliError(QStringLiteral("Dein Konto darf diese Sammlung nicht umbenennen."));
        }
    }

    const auto uncertain =
        QStringLiteral("Bitwarden hat die Ordneränderung nicht vollständig bestätigt. Versuche die Synchronisierung erneut.");
    QList<QJsonObject> results;
    results.reserve(edits.size());
    for (const auto& edit : edits) {
        auto folder = folders.byId.value(edit.id);
        if (folder.value(nameKey) != edit.newPath) {
            const auto id = uuidString(edit.id);
            QStringList arguments{QStringLiteral("edit"), shared ? QStringLiteral("org-collection") : QStringLiteral("folder"), id};
            QJsonObject payload{{nameKey, edit.newPath}};
            if (shared) {
                const auto organization = uuidString(organizationId);
                const QStringList scope{QStringLiteral("--organizationid"), organization};
                arguments.append(scope);
                const auto details = parseObject(run(QStringList{QStringLiteral("get"), QStringLiteral("org-collection"), id} + scope));
                const auto externalId = details.value(QStringLiteral("externalId"));
                if (details.value(idKey) != id || details.value(organizationIdKey) != organization
                    || details.value(nameKey) != edit.oldPath || !details.value(canRenameKey).toBool()
                    || !validAccessList(details.value(QStringLiteral("users")))
                    || !validAccessList(details.value(QStringLiteral("groups"))) || !optionalString(externalId)) {
                    throw BitwardenCliError(
                        QStringLiteral("Bitwarden hat keine vollständigen Sammlungsrechte geliefert. Die Sammlung wurde nicht geändert."),
                        BitwardenCliError::Reason::Conflict);
                }
                payload.insert(organizationIdKey, organization);
                payload.insert(QStringLiteral("users"), details.value(QStringLiteral("users")));
                payload.insert(QStringLiteral("groups"), details.value(QStringLiteral("groups")));
                if (hasValue(externalId)) {
                    payload.insert(QStringLiteral("externalId"), externalId);
                }
            }
            QJsonObject saved;
            try {
                saved = writeObject(arguments, payload);
            } catch (const BitwardenCliError& error) {
                throw BitwardenCliError(uncertain, error.reason());
            }
            if (saved.value(idKey) != id || saved.value(nameKey) != edit.newPath
                || (shared && saved.value(organizationIdKey) != uuidString(organizationId))) {
                throw BitwardenCliError(uncertain);
            }
            if (shared) {
                folder.insert(nameKey, edit.newPath);
            } else {
                folder = std::move(saved);
            }
        }
        results.append(std::move(folder));
    }
    return results;
}

void BitwardenCli::deleteFolder(const QUuid& id, const QString& expectedPath)
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    if (id.isNull() || expectedPath.isEmpty() || expectedPath.contains(QChar::Null)) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-Ordnerkennung oder der Ordnerpfad ist ungültig."));
    }

    // Recheck after an uncertain reply without targeting any replacement at the same path.
    syncVault(true);
    const FolderIndex folders(parseArray(run({QStringLiteral("list"), QStringLiteral("folders")})));
    const auto existing = folders.byId.constFind(id);
    if (existing == folders.byId.constEnd()) {
        return;
    }
    if (existing.value().value(nameKey) != expectedPath) {
        throw BitwardenCliError(
            QStringLiteral("Der Bitwarden-Ordner wurde auf einem anderen Gerät geändert."),
            BitwardenCliError::Reason::Conflict);
    }

    try {
        run({QStringLiteral("delete"), QStringLiteral("folder"), id.toString(QUuid::WithoutBraces)});
    } catch (const BitwardenCliError& error) {
        if (error.reason() != BitwardenCliError::Reason::Failed) {
            throw;
        }
        throw BitwardenCliError(QStringLiteral("Bitwarden hat das Löschen des Ordners nicht bestätigt."),
                               BitwardenCliError::Reason::WriteUncertain);
    }
}

QJsonObject BitwardenCli::writeObject(const QStringList& arguments, const QJsonObject& object) const
{
    auto input = encodeJson(QJsonDocument(object));
    const auto erase = qScopeGuard([&input] { input.fill('\0'); });
    return parseObject(run(arguments, input));
}

QJsonObject BitwardenCli::writeArray(const QStringList& arguments, const QJsonArray& array) const
{
    auto input = encodeJson(QJsonDocument(array));
    const auto erase = qScopeGuard([&input] { input.fill('\0'); });
    return parseObject(run(arguments, input));
}

QJsonArray BitwardenCli::listCollections(const QUuid& organizationId) const
{
    return parseArray(run({QStringLiteral("list"), QStringLiteral("collections"), QStringLiteral("--organizationid"),
                           uuidString(organizationId)}));
}

void BitwardenCli::ensureOrganizationWrites()
{
    if (cliVersion() != organizationWritesVersion) {
        throw BitwardenCliError(QStringLiteral("Für Änderungen an Organisationen ist die aktuelle BitwardenXC-CLI erforderlich."));
    }
}

QJsonObject BitwardenCli::checkRevision(const QString& id, const QString& expectedRevision) const
{
    if (expectedRevision.isEmpty()) {
        throw BitwardenCliError(QStringLiteral("Für den Eintrag fehlt die zuletzt gelesene Version."),
                               BitwardenCliError::Reason::Conflict);
    }
    syncVault(true);
    const auto latest = parseObject(run({QStringLiteral("get"), QStringLiteral("item"), id}));
    if (latest.value(QStringLiteral("id")) != id || latest.value(QStringLiteral("revisionDate")) != expectedRevision) {
        throw BitwardenCliError(QStringLiteral("Der Eintrag wurde auf einem anderen Gerät geändert. Lade ihn erneut."),
                               BitwardenCliError::Reason::Conflict);
    }
    return latest;
}

void BitwardenCli::adoptSessionKey(QByteArray key)
{
    auto decoded = QByteArray::fromBase64(key);
    const auto erase = qScopeGuard([&decoded] { decoded.fill('\0'); });
    if (decoded.size() != 64 || decoded.toBase64() != key) {
        key.fill('\0');
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat keinen gültigen Sitzungsschlüssel geliefert."));
    }
    clearSessionKey();
    m_sessionKey = std::move(key);
}

QJsonObject BitwardenCli::saveSessionKey(QByteArray key)
{
    const auto wipeKey = qScopeGuard([&key] { key.fill('\0'); });
    adoptSessionKey(key.trimmed());
    auto eraseOnFailure = qScopeGuard([this] { clearSessionKey(); });
    const auto status = profileStatus();
    if (status.value(QStringLiteral("status")) != QStringLiteral("unlocked")) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat den Tresor nicht entsperrt."),
                               BitwardenCliError::Reason::AuthenticationRequired);
    }
    eraseOnFailure.dismiss();
    return status;
}

void BitwardenCli::clearSessionKey()
{
    m_sessionKey.fill('\0');
    m_sessionKey.clear();
}

void BitwardenCli::ensureUnlocked() const
{
    if (m_sessionKey.isEmpty()) {
        throw BitwardenCliError(QStringLiteral("Entsperre zuerst den Tresor."), BitwardenCliError::Reason::AuthenticationRequired);
    }
}

QByteArray BitwardenCli::run(const QStringList& arguments,
                            const QByteArray& input,
                            const QProcessEnvironment& secrets) const
{
    auto environment = QProcessEnvironment::systemEnvironment();
    for (const auto& key : environment.keys()) {
        const auto name = key.toUpper();
        if (name.startsWith(QStringLiteral("BW_")) || name.startsWith(QStringLiteral("BITWARDENCLI_"))
            || name.startsWith(QStringLiteral("NODE_")) || name == QStringLiteral("SSLKEYLOGFILE")
            || name == QStringLiteral("SSL_CERT_FILE") || name == QStringLiteral("SSL_CERT_DIR")) {
            environment.remove(key);
        }
    }
    environment.remove(passwordVariable);
    environment.insert(QStringLiteral("BITWARDENCLI_APPDATA_DIR"), m_profileDir);
    if (!m_sessionKey.isEmpty()) {
        environment.insert(sessionVariable, QString::fromLatin1(m_sessionKey));
    }
    environment.insert(secrets);

    QProcess process;
    process.setProgram(m_executable);
    process.setArguments(QStringList{QStringLiteral("--nointeraction"), QStringLiteral("--raw")} + arguments);
    process.setProcessEnvironment(environment);
    process.setWorkingDirectory(m_profileDir);
    process.start();
    if (!process.waitForStarted(5000)) {
        throw BitwardenCliError(QStringLiteral("Die ausgewählte Bitwarden-CLI konnte nicht gestartet werden."));
    }
    const auto stop = qScopeGuard([&process] {
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            process.waitForFinished(3000);
        }
    });

    if (!input.isEmpty() && process.write(input) != input.size()) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI konnte die Eingabe nicht empfangen."));
    }
    process.closeWriteChannel();

    QByteArray output;
    QByteArray diagnostics;
    const auto erase = qScopeGuard([&] {
        output.fill('\0');
        diagnostics.fill('\0');
    });
    const auto readOutput = [&] {
        output += process.readAllStandardOutput();
        diagnostics += process.readAllStandardError();
        if (output.size() > outputLimit || diagnostics.size() > diagnosticsLimit) {
            throw BitwardenCliError(QStringLiteral("Die Ausgabe der Bitwarden-CLI überschreitet das Limit."));
        }
    };

    QDeadlineTimer deadline(commandTimeoutMs);
    while (process.state() != QProcess::NotRunning && !deadline.hasExpired()) {
        process.waitForReadyRead(static_cast<int>(std::min<qint64>(deadline.remainingTime(), 100)));
        readOutput();
    }
    if (process.state() != QProcess::NotRunning) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat nicht rechtzeitig geantwortet."));
    }
    readOutput();
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        commandFailed(diagnostics);
    }
    return QByteArray(std::move(output));
}
