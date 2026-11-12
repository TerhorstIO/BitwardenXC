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
#include <QJsonDocument>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QScopeGuard>
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
    const auto nameKey = QStringLiteral("name");
    const auto notesKey = QStringLiteral("notes");
    const auto idKey = QStringLiteral("id");
    const auto loginKey = QStringLiteral("login");
    const auto urisKey = QStringLiteral("uris");
    const auto uriKey = QStringLiteral("uri");
    const auto matchKey = QStringLiteral("match");
    const auto fieldsKey = QStringLiteral("fields");
    const auto folderIdKey = QStringLiteral("folderId");
    const QStringList loginTextKeys{QStringLiteral("username"), QStringLiteral("password"), QStringLiteral("totp")};
    constexpr int commandTimeoutMs = 60000;
    constexpr qsizetype outputLimit = 64 * 1024 * 1024;
    constexpr qsizetype diagnosticsLimit = 256 * 1024;

    QDateTime lastSync(const QJsonObject& status)
    {
        return QDateTime::fromString(status.value(QStringLiteral("lastSync")).toString(), Qt::ISODateWithMs);
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

    QProcessEnvironment passwordEnvironment(const QByteArray& password)
    {
        if (password.isEmpty() || password.contains('\0')) {
            throw BitwardenCliError(QStringLiteral("Gib dein Master-Passwort ein."));
        }
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

    QByteArray encodeItem(const QJsonObject& item)
    {
        auto json = QJsonDocument(item).toJson(QJsonDocument::Compact);
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
    return cliVersion() == fullEditingVersion;
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
    const auto reportedServer = result.value(QStringLiteral("serverUrl")).toString();
    const auto activeServer = reportedServer.isEmpty() ? defaultServer : serverAddress(QUrl(reportedServer));
    const auto activeEmail = result.value(QStringLiteral("userEmail")).toString();
    if (activeServer != m_server || activeEmail.compare(m_email, Qt::CaseInsensitive) != 0) {
        throw BitwardenCliError(QStringLiteral("Der angemeldete Bitwarden-Tresor passt nicht zum ausgewählten Profil."));
    }
    return result;
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
    return (m_cliVersion == upstreamVersion || m_cliVersion == fullEditingVersion) && syncedAt.isValid()
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
    QStringList arguments{QStringLiteral("sync")};
    if (force) {
        arguments.append(QStringLiteral("--force"));
    }
    run(arguments);
}

QJsonArray BitwardenCli::listFolders()
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    return parseArray(run({QStringLiteral("list"), QStringLiteral("folders")}));
}

QJsonArray BitwardenCli::listItems()
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    return parseArray(run({QStringLiteral("list"), QStringLiteral("items")}));
}

QJsonObject BitwardenCli::editItem(const QString& id, const QJsonObject& item, const QString& expectedRevision)
{
    const QMutexLocker locker(&m_mutex);
    ensureUnlocked();
    const auto canonicalId = itemId(id);
    const bool fullEdit = item.contains(loginKey) || item.contains(fieldsKey) || item.contains(folderIdKey);
    if (fullEdit && cliVersion() != fullEditingVersion) {
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
    const auto saved = writeItem({QStringLiteral("edit"), QStringLiteral("item"), canonicalId}, updated);
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
    for (auto field = item.constBegin(); field != item.constEnd(); ++field) {
        const auto& key = field.key();
        const auto& value = field.value();
        if ((key == typeKey && value.toInt() == 1) || (key == favoriteKey && value.isBool())
            || (key == repromptKey && (value.toInt(-1) == 0 || value.toInt(-1) == 1))
            || validItemField(key, value, true)) {
            continue;
        }
        throw BitwardenCliError(QStringLiteral("Der neue persönliche Login enthält ungültige Felder."));
    }
    if (item.value(nameKey).toString().trimmed().isEmpty() || !item.contains(loginKey)) {
        throw BitwardenCliError(QStringLiteral("Der neue Login benötigt einen Titel und Login-Daten."));
    }

    auto created = item;
    created.insert(typeKey, 1);
    created.insert(favoriteKey, item.value(favoriteKey).toBool());
    created.insert(repromptKey, item.value(repromptKey).toInt());
    created.insert(loginKey, loginForWrite(item.value(loginKey).toObject()));
    const auto saved = writeItem({QStringLiteral("create"), QStringLiteral("item")}, created);
    if (!validId(saved.value(idKey).toString())) {
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat den neuen Eintrag nicht bestätigt."));
    }
    return saved;
}

QJsonObject BitwardenCli::writeItem(const QStringList& arguments, const QJsonObject& item) const
{
    auto input = encodeItem(item);
    const auto erase = qScopeGuard([&input] { input.fill('\0'); });
    return parseObject(run(arguments, input));
}

QJsonObject BitwardenCli::checkRevision(const QString& id, const QString& expectedRevision) const
{
    if (expectedRevision.isEmpty()) {
        throw BitwardenCliError(QStringLiteral("Für den Eintrag fehlt die zuletzt gelesene Version."),
                               BitwardenCliError::Reason::Conflict);
    }
    run({QStringLiteral("sync"), QStringLiteral("--force")});
    const auto latest = parseObject(run({QStringLiteral("get"), QStringLiteral("item"), id}));
    if (latest.value(QStringLiteral("id")) != id || latest.value(QStringLiteral("revisionDate")) != expectedRevision) {
        throw BitwardenCliError(QStringLiteral("Der Eintrag wurde auf einem anderen Gerät geändert. Lade ihn erneut."),
                               BitwardenCliError::Reason::Conflict);
    }
    return latest;
}

QJsonObject BitwardenCli::saveSessionKey(QByteArray key)
{
    key = key.trimmed();
    auto decoded = QByteArray::fromBase64(key);
    const auto erase = qScopeGuard([&decoded] { decoded.fill('\0'); });
    if (decoded.size() != 64 || decoded.toBase64() != key) {
        key.fill('\0');
        throw BitwardenCliError(QStringLiteral("Die Bitwarden-CLI hat keinen gültigen Sitzungsschlüssel geliefert."));
    }
    clearSessionKey();
    m_sessionKey = std::move(key);
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
