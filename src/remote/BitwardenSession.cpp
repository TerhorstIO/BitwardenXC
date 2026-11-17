/*
 * Copyright (C) 2026 BitwardenXC contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "remote/BitwardenSession.h"

#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "core/Totp.h"

#include <QCoreApplication>
#include <QHash>
#include <QScopeGuard>
#include <QSet>

#include <algorithm>

namespace
{
    constexpr auto CompareVault = CompareItemIgnoreStatistics | CompareItemIgnoreHistory | CompareItemIgnoreLocation
        | CompareItemIgnoreDisabled;

    bool visibleItem(const QJsonObject& item)
    {
        const auto type = item.value("type").toInt();
        const auto reprompt = item.value("reprompt");
        return (type == 1 || type == 2) && item.value("name").isString() && item.value("deletedDate").toString().isEmpty()
            && item.value("archivedDate").toString().isEmpty()
            && (reprompt.isUndefined() || reprompt.isNull() || reprompt.toInt(-1) == 0);
    }

    bool personalLogin(const QJsonObject& item)
    {
        return item.value("type").toInt() == 1 && item.value("organizationId").toString().isEmpty()
            && item.value("edit").toBool(true) && item.value("viewPassword").toBool(true);
    }

    bool supportedFieldName(const QString& name)
    {
        return !name.trimmed().isEmpty() && !EntryAttributes::isDefaultAttribute(name)
            && !name.startsWith("KP2A_", Qt::CaseInsensitive) && !name.startsWith("KPXC_", Qt::CaseInsensitive)
            && !name.startsWith("KPEX_", Qt::CaseInsensitive) && !name.startsWith("TimeOtp-", Qt::CaseInsensitive)
            && name != EntryAttributes::RememberCmdExecAttr && name != Totp::ATTRIBUTE_OTP
            && name != Totp::ATTRIBUTE_SEED && name != Totp::ATTRIBUTE_SETTINGS;
    }

    QSet<QString> editableFieldNames(const QJsonArray& fields)
    {
        QHash<QString, int> names;
        for (const auto& value : fields) {
            ++names[value.toObject().value("name").toString()];
        }
        QSet<QString> editable;
        for (const auto& value : fields) {
            const auto field = value.toObject();
            const auto name = field.value("name").toString();
            const auto type = field.value("type").toInt(-1);
            if (names.value(name) == 1 && supportedFieldName(name) && (type == 0 || type == 1)) {
                editable.insert(name);
            }
        }
        return editable;
    }

    void setLoginFields(Entry& entry, const QJsonObject& item)
    {
        const auto login = item.value("login").toObject();
        const bool canViewPassword = item.value("viewPassword").toBool(true);
        entry.setUsername(login.value("username").toString());
        entry.setPassword(canViewPassword ? login.value("password").toString() : QString());
        if (canViewPassword) {
            QVariantList passkeys;
            const auto credentials = item.value("organizationId").toString().isEmpty()
                    || item.value("viewPassword").toBool()
                ? login.value("fido2Credentials").toArray()
                : QJsonArray();
            for (const auto& value : credentials) {
                if (!value.isObject()) {
                    continue;
                }
                const auto credential = value.toObject();
                passkeys.append(QVariantMap{{"rpId", credential.value("rpId").toString()},
                                             {"rpName", credential.value("rpName").toString()},
                                             {"userName", credential.value("userName").toString()},
                                             {"userDisplayName", credential.value("userDisplayName").toString()}});
            }
            if (!passkeys.isEmpty()) {
                entry.setProperty("bitwardenPasskeys", passkeys);
            }
        }
        const auto uris = login.value("uris").toArray();
        for (qsizetype i = 0; i < uris.size(); ++i) {
            const auto uri = uris.at(i).toObject().value("uri").toString();
            if (i == 0) {
                entry.setUrl(uri);
            } else if (!uri.isEmpty()) {
                entry.attributes()->set(QString("%1_%2").arg(EntryAttributes::AdditionalUrlAttribute).arg(i), uri);
            }
        }

        const auto totp = login.value("totp").toString();
        if (canViewPassword && !totp.isEmpty()) {
            const auto settings = totp.startsWith("otpauth://")
                ? totp
                : QString("otpauth://totp/Bitwarden?secret=%1").arg(QString::fromLatin1(QUrl::toPercentEncoding(totp)));
            entry.setTotp(Totp::parseSettings(settings));
        }

        const auto fields = item.value("fields").toArray();
        const auto editable = editableFieldNames(fields);
        for (const auto& value : fields) {
            const auto field = value.toObject();
            const auto name = field.value("name").toString();
            const auto hidden = field.value("type").toInt() == 1;
            if (editable.contains(name) && (!hidden || canViewPassword)) {
                entry.attributes()->set(name, field.value("value").toString(), hidden);
            }
        }
    }

    template <typename Item> void normalizeTimes(Item& expected, const Item& edited)
    {
        auto time = expected.timeInfo();
        time.setCreationTime(edited.timeInfo().creationTime());
        time.setLastModificationTime(edited.timeInfo().lastModificationTime());
        expected.setTimeInfo(time);
    }

    QSet<QUuid> childIds(const Group& group)
    {
        QSet<QUuid> ids;
        for (const auto* child : group.children()) {
            ids.insert(child->uuid());
        }
        return ids;
    }

    bool sameFolder(const Group& old, const Group& current)
    {
        return old.name() == current.name() && old.notes() == current.notes() && old.tags() == current.tags()
            && old.iconNumber() == current.iconNumber() && old.iconUuid() == current.iconUuid()
            && old.timeInfo().equals(current.timeInfo(), CompareVault)
            && old.defaultAutoTypeSequence() == current.defaultAutoTypeSequence()
            && old.autoTypeEnabled() == current.autoTypeEnabled() && old.searchingEnabled() == current.searchingEnabled()
            && old.mergeMode() == current.mergeMode() && *old.customData() == *current.customData()
            && childIds(old) == childIds(current);
    }

    QString folderPath(const QJsonArray& folders, const QUuid& id)
    {
        for (const auto& value : folders) {
            const auto folder = value.toObject();
            if (QUuid(folder.value("id").toString()) == id) {
                return folder.value("name").toString();
            }
        }
        return {};
    }

    qsizetype countFolderPath(const QJsonArray& folders, const QString& path)
    {
        return std::count_if(folders.begin(), folders.end(), [&path](const QJsonValue& value) {
            const auto folder = value.toObject();
            return !QUuid(folder.value("id").toString()).isNull() && folder.value("name") == path;
        });
    }

    QString idString(const QUuid& id)
    {
        return id.toString(QUuid::WithoutBraces);
    }

    void replaceFolder(QJsonArray& folders, const QJsonObject& folder)
    {
        for (qsizetype i = 0; i < folders.size(); ++i) {
            if (QUuid(folders.at(i).toObject().value("id").toString()) == QUuid(folder.value("id").toString())) {
                folders.replace(i, folder);
                return;
            }
        }
        folders.append(folder);
    }

    void removeFolder(QJsonArray& folders, const QUuid& id)
    {
        for (qsizetype i = folders.size(); i > 0; --i) {
            if (QUuid(folders.at(i - 1).toObject().value("id").toString()) == id) {
                folders.removeAt(i - 1);
            }
        }
    }

    QJsonObject folderRow(const QUuid& id, const QString& path)
    {
        return {{"object", "folder"}, {"id", idString(id)}, {"name", path}};
    }

    QList<QJsonObject> sortedFolders(const QJsonArray& values)
    {
        QList<QJsonObject> folders;
        for (const auto& value : values) {
            folders.append(value.toObject());
        }
        std::stable_sort(folders.begin(), folders.end(), [](const QJsonObject& left, const QJsonObject& right) {
            return left.value("name").toString().count('/') < right.value("name").toString().count('/');
        });
        return folders;
    }

    bool validFolderPath(const QString& path)
    {
        return !path.isEmpty() && !path.contains(QChar::Null) && !path.contains('\r') && !path.contains('\n');
    }

    QUuid organizationGroupId(const QUuid& id, const QByteArray& type)
    {
        static const QUuid groupNamespace(QStringLiteral("45273921-667d-4368-b93a-fbdf6050dc50"));
        return QUuid::createUuidV5(groupNamespace, type + id.toRfc4122());
    }

    QUuid collectionGroupId(const QUuid& organization, const QUuid& collection)
    {
        return organizationGroupId(collection, "collection" + organization.toRfc4122());
    }

    QJsonArray organizationCollections(const QJsonArray& allCollections, const QUuid& organization)
    {
        QJsonArray collections;
        for (const auto& value : allCollections) {
            if (QUuid(value.toObject().value("organizationId").toString()) == organization) {
                collections.append(value);
            }
        }
        return collections;
    }

    struct OrganizationGroups
    {
        QHash<QUuid, Group*> vaults;
        QHash<QUuid, QHash<QUuid, Group*>> collections;
    };

    OrganizationGroups buildOrganizationGroups(Group* container, const BitwardenCli::VaultSnapshot& snapshot)
    {
        OrganizationGroups groups;
        const auto addVault = [&groups, container](const QUuid& id, const QString& name) {
            if (id.isNull() || groups.vaults.contains(id)) {
                return;
            }
            auto* group = new Group();
            group->setUuid(organizationGroupId(id, "organization"));
            group->setName(name.isEmpty() ? QObject::tr("Organization (%1)").arg(idString(id).left(8)) : name);
            group->setProperty("bitwardenOrganization", true);
            group->setParent(container);
            groups.vaults.insert(id, group);
        };
        for (const auto& value : snapshot.organizations) {
            const auto organization = value.toObject();
            addVault(QUuid(organization.value("id").toString()), organization.value("name").toString());
        }
        // The previous bundled CLI can open an encrypted cache without organization metadata.
        for (const auto& value : snapshot.items) {
            const auto item = value.toObject();
            if (visibleItem(item)) {
                addVault(QUuid(item.value("organizationId").toString()), {});
            }
        }

        QHash<QUuid, QHash<QString, Group*>> paths;
        for (const auto& collection : sortedFolders(snapshot.collections)) {
            const QUuid organizationId(collection.value("organizationId").toString());
            const QUuid id(collection.value("id").toString());
            const auto path = collection.value("name").toString();
            auto* vault = groups.vaults.value(organizationId);
            if (!vault || id.isNull() || path.isEmpty() || groups.collections[organizationId].contains(id)) {
                continue;
            }
            auto& organizationPaths = paths[organizationId];
            const auto separator = path.lastIndexOf('/');
            auto* parent = separator > 0 ? organizationPaths.value(path.left(separator), vault) : vault;
            auto* group = new Group();
            group->setUuid(collectionGroupId(organizationId, id));
            group->setName(parent == vault ? path : path.mid(separator + 1));
            group->setProperty("bitwardenCollection", true);
            group->setParent(parent);
            groups.collections[organizationId].insert(id, group);
            if (!organizationPaths.contains(path)) {
                organizationPaths.insert(path, group);
            }
        }
        return groups;
    }

    BitwardenCliError unsupportedChange()
    {
        return BitwardenCliError(QObject::tr("This change is not supported for the connected Bitwarden vault."));
    }

    QJsonArray updatedFields(const Entry& entry, Entry* expected, const QJsonArray& original)
    {
        const auto editable = editableFieldNames(original);
        QSet<QString> existing;
        QJsonArray fields;
        const auto* attributes = entry.attributes();
        for (const auto& value : original) {
            auto field = value.toObject();
            const auto name = field.value("name").toString();
            existing.insert(name);
            if (!editable.contains(name)) {
                fields.append(value);
            } else if (attributes->hasKey(name)) {
                if (attributes->value(name) != field.value("value").toString()) {
                    field.insert("value", attributes->value(name));
                }
                field.insert("type", attributes->isProtected(name) ? 1 : 0);
                fields.append(field);
                if (expected) {
                    expected->attributes()->set(name, attributes->value(name), attributes->isProtected(name));
                }
            } else if (expected) {
                expected->attributes()->remove(name);
            }
        }
        for (const auto& name : attributes->customKeys()) {
            if (!supportedFieldName(name)) {
                continue;
            }
            if (existing.contains(name)) {
                if (!editable.contains(name)) {
                    throw unsupportedChange();
                }
                continue;
            }
            fields.append(QJsonObject{{"name", name},
                                      {"value", attributes->value(name)},
                                      {"type", attributes->isProtected(name) ? 1 : 0}});
            if (expected) {
                expected->attributes()->set(name, attributes->value(name), attributes->isProtected(name));
            }
        }
        return fields;
    }

    QJsonValue folderFor(const Entry& entry, const QUuid& rootId)
    {
        const auto id = entry.group()->uuid();
        return id == rootId ? QJsonValue(QJsonValue::Null) : QJsonValue(id.toString(QUuid::WithoutBraces));
    }

    void copyTotpAttributes(const Entry& entry, Entry& expected)
    {
        for (const auto& key : {Totp::ATTRIBUTE_OTP, Totp::ATTRIBUTE_SEED, Totp::ATTRIBUTE_SETTINGS}) {
            if (entry.attributes()->hasKey(key)) {
                expected.attributes()->set(key, entry.attributes()->value(key), entry.attributes()->isProtected(key));
            } else {
                expected.attributes()->remove(key);
            }
        }
    }

    QJsonObject updatedLogin(const Entry& entry, Entry& expected, const QJsonObject& item, bool fullEditing)
    {
        QJsonObject fields;
        const auto totp = Totp::writeSettings(entry.totpSettings(), {}, {}, true);
        const auto previousTotp = Totp::writeSettings(expected.totpSettings(), {}, {}, true);
        if (totp == previousTotp) {
            copyTotpAttributes(entry, expected);
        }
        if (!personalLogin(item)) {
            return fields;
        }
        if (entry.title() != expected.title()) {
            if (entry.title().trimmed().isEmpty()) {
                throw BitwardenCliError(QObject::tr("Enter a title for the Bitwarden login."));
            }
            expected.setTitle(entry.title());
            fields.insert("name", entry.title());
        }
        if (entry.notes() != expected.notes()) {
            expected.setNotes(entry.notes());
            fields.insert("notes", entry.notes());
        }
        if (!fullEditing) {
            return fields;
        }

        QJsonObject login;
        if (entry.username() != expected.username()) {
            expected.setUsername(entry.username());
            login.insert("username", entry.username());
        }
        if (entry.password() != expected.password()) {
            expected.setPassword(entry.password());
            login.insert("password", entry.password());
        }
        if (entry.url() != expected.url()) {
            auto uris = item.value("login").toObject().value("uris").toArray();
            if (entry.url().isEmpty()) {
                if (uris.size() > 1) {
                    throw BitwardenCliError(QObject::tr("Enter a first URL to keep this login's additional URLs."));
                }
                uris = {};
            } else if (uris.isEmpty()) {
                uris.append(QJsonObject{{"uri", entry.url()}});
            } else {
                auto first = uris.at(0).toObject();
                first.insert("uri", entry.url());
                uris.replace(0, first);
            }
            expected.setUrl(entry.url());
            login.insert("uris", uris);
        }
        if (totp != previousTotp) {
            expected.setTotp(entry.totpSettings());
            copyTotpAttributes(entry, expected);
            login.insert("totp", totp.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(totp));
        }
        if (!login.isEmpty()) {
            fields.insert("login", login);
        }
        const auto originalFields = item.value("fields").toArray();
        const auto newFields = updatedFields(entry, &expected, originalFields);
        if (newFields != originalFields) {
            fields.insert("fields", newFields);
        }
        return fields;
    }

    QJsonObject newLogin(const Entry& entry, const QUuid& rootId)
    {
        if (entry.title().trimmed().isEmpty()) {
            throw BitwardenCliError(QObject::tr("Enter a title for the Bitwarden login."));
        }
        QJsonObject login{{"username", entry.username()}, {"password", entry.password()}};
        if (!entry.url().isEmpty()) {
            login.insert("uris", QJsonArray{QJsonObject{{"uri", entry.url()}}});
        }
        const auto totp = entry.totpSettingsString();
        if (!totp.isEmpty()) {
            login.insert("totp", totp);
        }
        return {{"type", 1},
                {"name", entry.title()},
                {"notes", entry.notes()},
                {"folderId", folderFor(entry, rootId)},
                {"fields", updatedFields(entry, nullptr, {})},
                {"login", login}};
    }
} // namespace

BitwardenSession::BitwardenSession(QString executable, QUrl server, QString email)
    : m_cli(executable, server, email)
    , m_name(QObject::tr("Bitwarden · %1").arg(email))
{
}

QString BitwardenSession::stageText(OpenStage stage)
{
    switch (stage) {
    case OpenStage::CheckingProfile:
        return QCoreApplication::translate("BitwardenSession", "Preparing the Bitwarden CLI…");
    case OpenStage::OpeningCache:
        return QCoreApplication::translate("BitwardenSession", "Opening the encrypted local vault cache…");
    case OpenStage::Authenticating:
        return QCoreApplication::translate("BitwardenSession", "Signing in or unlocking the Bitwarden vault…");
    case OpenStage::Synchronizing:
        return QCoreApplication::translate("BitwardenSession", "Synchronizing with the Bitwarden server…");
    case OpenStage::ReadingVault:
        return QCoreApplication::translate("BitwardenSession", "Reading and decrypting folders and entries…");
    case OpenStage::PreparingView:
        return QCoreApplication::translate("BitwardenSession", "Preparing the vault view…");
    }
    return {};
}

void BitwardenSession::connect(QByteArray password,
                               QString code,
                               QString clientId,
                               QByteArray clientSecret,
                               const OpenProgress& progress)
{
    const auto wipe = qScopeGuard([&] {
        password.fill('\0');
        code.fill(QChar());
        clientId.fill(QChar());
        clientSecret.fill('\0');
    });
    if (progress) {
        progress(OpenStage::CheckingProfile);
    }
    m_fullEditing = m_cli.supportsFullEditing();
    if (code.isEmpty() && clientId.isEmpty() && openCachedVault(password, progress)) {
        return;
    }
    if (progress) {
        progress(OpenStage::Authenticating);
    }
    const auto alreadySynced = m_cli.connect(password, code, clientId, clientSecret);
    loadFolderWrites(password);
    loadVault(!alreadySynced, false, progress);
}

bool BitwardenSession::openCachedVault(const QByteArray& password, const OpenProgress& progress)
{
    if (progress) {
        progress(OpenStage::OpeningCache);
    }
    auto cached = m_cli.openCachedVault(password);
    if (!cached) {
        return false;
    }
    loadFolderWrites(password);
    setVault(std::move(*cached), true);
    return true;
}

void BitwardenSession::loadVault(bool synchronize, bool force, const OpenProgress& progress)
{
    if (synchronize) {
        if (progress) {
            progress(OpenStage::Synchronizing);
        }
        m_cli.sync(force);
    }
    if (progress) {
        progress(OpenStage::ReadingVault);
    }
    setVault(m_cli.readVault(false), false);
}

void BitwardenSession::setVault(VaultSnapshot snapshot, bool needsInitialSync)
{
    m_confirmedFolders = std::move(snapshot.folders);
    projectFolderWrites();
    m_items = std::move(snapshot.items);
    m_organizations = std::move(snapshot.organizations);
    m_collections = std::move(snapshot.collections);
    rebuildCollectionIndex();
    m_connected = true;
    m_needsInitialSync = needsInitialSync;
}

bool BitwardenSession::needsInitialSync() const
{
    return m_needsInitialSync;
}

QUuid BitwardenSession::personalRootId() const
{
    return m_rootId;
}

BitwardenSession::VaultSnapshot BitwardenSession::fetchSync(bool force, const std::function<bool()>& canceled)
{
    return m_cli.readVault(true, force, canceled);
}

QSharedPointer<Database> BitwardenSession::applySync(VaultSnapshot snapshot)
{
    if (!m_connected || hasPendingFolderWrites()) {
        return {};
    }
    if (snapshot.folders == m_folders && snapshot.items == m_items && snapshot.organizations == m_organizations
        && snapshot.collections == m_collections) {
        m_needsInitialSync = false;
        return {};
    }
    auto database = makeDatabase(snapshot);
    setVault(std::move(snapshot), false);
    return database;
}

void BitwardenSession::unlock(QByteArray password, const OpenProgress& progress)
{
    const auto wipe = qScopeGuard([&password] { password.fill('\0'); });
    try {
        if (openCachedVault(password, progress)) {
            return;
        }
        if (progress) {
            progress(OpenStage::Authenticating);
        }
        m_cli.unlock(password);
        loadFolderWrites(password);
        loadVault(true, false, progress);
    } catch (...) {
        try {
            lock();
        } catch (...) {
            // The adapter clears its session key even if the CLI lock fails.
        }
        throw;
    }
}

void BitwardenSession::lock()
{
    m_items = {};
    m_organizations = {};
    m_collections = {};
    m_collectionIndexes.clear();
    m_stagedEntryMoves.clear();
    m_folders = {};
    m_confirmedFolders = {};
    m_folderWrites.clear();
    m_folderQueueError.clear();
    m_pendingFolderAliases.clear();
    m_folderJournal.lock();
    m_connected = false;
    m_needsInitialSync = false;
    m_cli.lock();
}

bool BitwardenSession::canCreate() const
{
    return m_connected;
}

bool BitwardenSession::supportsFullEditing() const
{
    return m_fullEditing;
}

bool BitwardenSession::isEditableFieldName(const QString& name)
{
    return supportedFieldName(name);
}

bool BitwardenSession::canEdit(const QUuid& id) const
{
    if (!m_connected || id.isNull()) {
        return false;
    }
    for (const auto& value : m_items) {
        const auto item = value.toObject();
        if (QUuid(item.value("id").toString()) == id) {
            return visibleItem(item) && personalLogin(item);
        }
    }
    return true;
}

bool BitwardenSession::isDraft(const QUuid& id) const
{
    return m_connected && !id.isNull() && std::none_of(m_items.begin(), m_items.end(), [&id](const QJsonValue& item) {
        return QUuid(item.toObject().value("id").toString()) == id;
    });
}

QSharedPointer<Database> BitwardenSession::makeDatabase() const
{
    return makeDatabase({m_folders, m_items, m_organizations, m_collections});
}

void BitwardenSession::loadFolderWrites(const QByteArray& password)
{
    m_folderQueueError.clear();
    try {
        restoreFolderWrites(m_folderJournal.unlock(m_cli.folderJournalPath(), password));
    } catch (const BitwardenCliError& error) {
        m_folderJournal.lock();
        m_folderWrites.clear();
        m_folderQueueError = error.message();
    }
}

void BitwardenSession::restoreFolderWrites(const QJsonArray& records)
{
    QList<FolderWrite> writes;
    QSet<QUuid> writeIds;
    const auto badJournal = [] {
        return BitwardenCliError(QObject::tr("The local Bitwarden folder queue is invalid."));
    };
    for (const auto& value : records) {
        const auto outer = value.toObject();
        const bool organizationWrite = outer.contains("organizationWrite");
        const auto record = organizationWrite ? outer.value("organizationWrite").toObject() : outer;
        FolderWrite write;
        write.id = QUuid(record.value("id").toString());
        write.organizationId = QUuid(record.value("organizationId").toString());
        write.parent = QUuid(record.value("parent").toString());
        write.attempted = record.value("attempted").toBool();
        write.deleteId = QUuid(record.value("deleteId").toString());
        write.path = record.value(write.deleteId.isNull() ? "path" : "deletePath").toString();
        if (write.id.isNull() || writeIds.contains(write.id)
            || (!record.value("parent").toString().isEmpty() && write.parent.isNull())
            || (!record.value("deleteId").toString().isEmpty() && write.deleteId.isNull())
            || (organizationWrite != !write.organizationId.isNull())
            || (organizationWrite && !write.deleteId.isNull())
            || !record.value("edits").isArray()) {
            throw badJournal();
        }
        QSet<QUuid> editIds;
        for (const auto& editValue : record.value("edits").toArray()) {
            const auto edit = editValue.toObject();
            const QUuid id(edit.value("id").toString());
            const auto oldPath = edit.value("oldPath").toString();
            const auto newPath = edit.value("newPath").toString();
            if (id.isNull() || editIds.contains(id) || !validFolderPath(oldPath) || !validFolderPath(newPath)) {
                throw badJournal();
            }
            write.edits.append({id, oldPath, newPath});
            editIds.insert(id);
        }
        if (write.edits.isEmpty() ? !validFolderPath(write.path) : !write.path.isEmpty()) {
            throw badJournal();
        }
        if (!write.deleteId.isNull() && (!write.edits.isEmpty() || !write.parent.isNull() || write.attempted
                                       || !record.value("path").toString().isEmpty())) {
            throw badJournal();
        }
        writeIds.insert(write.id);
        writes.append(std::move(write));
    }
    m_folderWrites = std::move(writes);
}

void BitwardenSession::storeFolderWrites(QList<FolderWrite> writes)
{
    QJsonArray records;
    for (const auto& write : writes) {
        QJsonArray edits;
        for (const auto& edit : write.edits) {
            edits.append(QJsonObject{{"id", idString(edit.id)}, {"oldPath", edit.oldPath}, {"newPath", edit.newPath}});
        }
        QJsonObject record{{"id", idString(write.id)},
                           {"parent", write.parent.isNull() ? QString() : idString(write.parent)},
                           {"attempted", write.attempted},
                           {"edits", edits}};
        if (write.deleteId.isNull()) {
            record.insert("path", write.path);
        } else {
            // Older clients reject this record instead of replaying the deletion as a create.
            record.insert("deleteId", idString(write.deleteId));
            record.insert("deletePath", write.path);
        }
        if (write.organizationId.isNull()) {
            records.append(record);
        } else {
            // A client unaware of collection writes must not replay this record as a personal folder change.
            record.insert("organizationId", idString(write.organizationId));
            records.append(QJsonObject{{"organizationWrite", record}});
        }
    }
    m_folderJournal.save(records);
    m_folderWrites = std::move(writes);
}

bool BitwardenSession::hasPendingFolderWrites() const
{
    return !m_folderWrites.isEmpty();
}

QString BitwardenSession::folderQueueError() const
{
    return m_folderQueueError;
}

bool BitwardenSession::isPendingFolder(const QUuid& id) const
{
    return std::any_of(m_folderWrites.begin(), m_folderWrites.end(), [&id](const FolderWrite& write) {
        return write.organizationId.isNull() && write.isCreate() && write.id == id;
    });
}

void BitwardenSession::rebuildCollectionIndex()
{
    m_collectionIndexes.clear();
    for (qsizetype i = 0; i < m_collections.size(); ++i) {
        const auto collection = m_collections.at(i).toObject();
        const QUuid organization(collection.value("organizationId").toString());
        const QUuid id(collection.value("id").toString());
        if (!organization.isNull() && !id.isNull()) {
            m_collectionIndexes.insert(collectionGroupId(organization, id), i);
        }
    }
}

QJsonObject BitwardenSession::collectionForGroup(const QUuid& id) const
{
    const auto index = m_collectionIndexes.value(id, -1);
    return index < 0 ? QJsonObject() : m_collections.at(index).toObject();
}

QJsonObject BitwardenSession::organizationForGroup(const QUuid& id) const
{
    const QUuid collectionOrganization(collectionForGroup(id).value("organizationId").toString());
    for (const auto& value : m_organizations) {
        const auto organization = value.toObject();
        const QUuid remoteId(organization.value("id").toString());
        if (!remoteId.isNull()
            && (remoteId == collectionOrganization || organizationGroupId(remoteId, "organization") == id)) {
            return organization;
        }
    }
    return {};
}

QUuid BitwardenSession::folderScopeId(const QUuid& id) const
{
    if (!m_connected || id.isNull()) {
        return {};
    }
    if (id == m_rootId || validFolderPath(folderPath(m_folders, id))) {
        return m_rootId;
    }
    const QUuid org(organizationForGroup(id).value("id").toString());
    return org.isNull() ? QUuid() : organizationGroupId(org, "organization");
}

bool BitwardenSession::hasPendingCollectionWrite(const QUuid& organizationId) const
{
    return std::any_of(m_folderWrites.begin(), m_folderWrites.end(), [&organizationId](const FolderWrite& write) {
        return write.organizationId == organizationId;
    });
}

bool BitwardenSession::canEditFolder(const QUuid& id) const
{
    if (!m_connected || id.isNull() || id == m_rootId) {
        return false;
    }
    if (validFolderPath(folderPath(m_folders, id))) {
        return true;
    }
    const auto collection = collectionForGroup(id);
    const QUuid org(organizationForGroup(id).value("id").toString());
    return !org.isNull() && collection.value("canRename").toBool() && !hasPendingCollectionWrite(org);
}

bool BitwardenSession::canUseFolderAsParent(const QUuid& id) const
{
    const auto scope = folderScopeId(id);
    if (scope.isNull()) {
        return false;
    }
    if (id == scope) {
        return true;
    }
    if (scope == m_rootId) {
        return countFolderPath(m_folders, folderPath(m_folders, id)) == 1;
    }
    const auto collection = collectionForGroup(id);
    const QUuid organizationId(collection.value("organizationId").toString());
    return countFolderPath(organizationCollections(m_collections, organizationId), collection.value("name").toString())
        == 1;
}

bool BitwardenSession::canCreateFolder(const QUuid& id) const
{
    if (!canUseFolderAsParent(id)) {
        return false;
    }
    if (folderScopeId(id) == m_rootId) {
        return true;
    }
    const auto organization = organizationForGroup(id);
    const QUuid organizationId(organization.value("id").toString());
    return !organizationId.isNull() && organization.value("canCreateCollections").toBool()
        && !hasPendingCollectionWrite(organizationId);
}

bool BitwardenSession::canDeleteFolder(const QUuid& id) const
{
    return id != m_rootId && folderScopeId(id) == m_rootId && canEditFolder(id);
}

bool BitwardenSession::canCreateInGroup(const QUuid& group) const
{
    if (!m_connected) {
        return false;
    }
    if (folderScopeId(group) == m_rootId) {
        return !isPendingFolder(group);
    }
    return m_fullEditing && !organizationForGroup(group).isEmpty()
        && collectionForGroup(group).value("canWriteItems").toBool();
}

std::optional<BitwardenSession::ItemMove>
BitwardenSession::entryMove(const QUuid& entry, const QUuid& sourceView, const QUuid& destination) const
{
    const auto target = collectionForGroup(destination);
    const QUuid destinationOrganization(target.value("organizationId").toString());
    const QUuid destinationCollection(target.value("id").toString());
    if (!m_fullEditing || entry.isNull() || !canCreateInGroup(destination) || destinationOrganization.isNull()
        || destinationCollection.isNull()) {
        return std::nullopt;
    }
    for (const auto& value : m_items) {
        const auto item = value.toObject();
        if (QUuid(item.value("id").toString()) != entry) {
            continue;
        }
        if (!visibleItem(item) || item.value("revisionDate").toString().isEmpty()) {
            return std::nullopt;
        }
        const QUuid owner(item.value("organizationId").toString());
        if (item.value("organizationId").toString().isEmpty()) {
            if (item.value("edit").toBool(true) && item.value("viewPassword").toBool(true)) {
                return ItemMove{{}, destinationOrganization, {}, destinationCollection};
            }
            return std::nullopt;
        }
        if (owner != destinationOrganization || !item.value("edit").toBool() || !item.value("viewPassword").toBool()) {
            return std::nullopt;
        }

        auto source = collectionForGroup(sourceView);
        const auto memberships = item.value("collectionIds").toArray();
        if (source.isEmpty() && memberships.size() == 1) {
            source = collectionForGroup(collectionGroupId(owner, QUuid(memberships.first().toString())));
        }
        QUuid sourceCollection;
        if (QUuid(source.value("organizationId").toString()) == owner) {
            const QUuid selected(source.value("id").toString());
            const auto selectedMember = std::any_of(memberships.begin(), memberships.end(), [&selected](const auto& id) {
                return QUuid(id.toString()) == selected;
            });
            if (selectedMember && !source.value("canWriteItems").toBool()) {
                return std::nullopt;
            }
            if (selectedMember) {
                sourceCollection = selected;
            }
        }
        const auto alreadyInTarget =
            std::any_of(memberships.begin(), memberships.end(), [&destinationCollection](const auto& id) {
                return QUuid(id.toString()) == destinationCollection;
            });
        if (sourceCollection == destinationCollection || (sourceCollection.isNull() && alreadyInTarget)) {
            return std::nullopt;
        }
        return ItemMove{owner, destinationOrganization, sourceCollection, destinationCollection};
    }
    return std::nullopt;
}

bool BitwardenSession::canMoveEntry(const QUuid& entry, const QUuid& sourceView, const QUuid& destination) const
{
    return entryMove(entry, sourceView, destination).has_value();
}

void BitwardenSession::stageEntryMove(const QUuid& entry, const QUuid& sourceView, const QUuid& destination)
{
    const auto move = entryMove(entry, sourceView, destination);
    if (!move) {
        throw BitwardenCliError(QObject::tr("You cannot move this entry to the selected Bitwarden collection."));
    }
    m_stagedEntryMoves.insert(entry, *move);
}

void BitwardenSession::clearStagedEntryMove(const QUuid& entry)
{
    m_stagedEntryMoves.remove(entry);
}

QString BitwardenSession::folderPathForWrite(const QUuid& parent, const QString& name) const
{
    if (!m_folderQueueError.isEmpty()) {
        throw BitwardenCliError(m_folderQueueError);
    }
    const auto leaf = name.trimmed();
    if (!validFolderPath(leaf) || leaf.contains('/')) {
        throw BitwardenCliError(QObject::tr("Enter a folder name without a slash or line break."));
    }
    if (!m_connected || parent.isNull()) {
        throw BitwardenCliError(QObject::tr("The selected Bitwarden vault or parent folder is unavailable."));
    }
    if (!canUseFolderAsParent(parent)) {
        throw BitwardenCliError(QObject::tr("The selected Bitwarden parent folder is missing or ambiguous."));
    }
    const auto scope = folderScopeId(parent);
    if (parent == scope) {
        return leaf;
    }
    if (scope != m_rootId) {
        return collectionForGroup(parent).value("name").toString() + '/' + leaf;
    }
    return folderPath(m_folders, parent) + '/' + leaf;
}

QUuid BitwardenSession::queueFolderCreate(Database& database, const QUuid& parent, const QString& name)
{
    const auto path = folderPathForWrite(parent, name);
    if (!canCreateFolder(parent)) {
        throw unsupportedChange();
    }
    const auto scope = folderScopeId(parent);
    const QUuid organization(organizationForGroup(parent).value("id").toString());
    const auto folders = organization.isNull() ? m_folders : organizationCollections(m_collections, organization);
    if (countFolderPath(folders, path) != 0) {
        throw BitwardenCliError(QObject::tr("A Bitwarden folder with this path already exists."),
                               BitwardenCliError::Reason::Conflict);
    }
    auto writes = m_folderWrites;
    const auto id = QUuid::createUuid();
    const auto parentId = parent == scope ? QUuid()
        : organization.isNull() ? parent : QUuid(collectionForGroup(parent).value("id").toString());
    writes.append({id, parentId, path, {}, false, {}, organization});
    storeFolderWrites(std::move(writes));
    if (!organization.isNull()) {
        return {};
    }
    projectFolderWrites();
    reconcileGroups(database);
    return id;
}

void BitwardenSession::queueFolderUpdate(Database& database, const QUuid& id, const QUuid& parent, const QString& name)
{
    const auto target = folderPathForWrite(parent, name);
    const auto scope = folderScopeId(id);
    if (!canEditFolder(id) || scope.isNull() || scope != folderScopeId(parent)) {
        throw BitwardenCliError(QObject::tr("The selected Bitwarden folder is missing or ambiguous."));
    }
    const QUuid organization(organizationForGroup(id).value("id").toString());
    const auto folders = organization.isNull() ? m_folders : organizationCollections(m_collections, organization);
    const auto remoteId = organization.isNull() ? id : QUuid(collectionForGroup(id).value("id").toString());
    const auto parentId = parent == scope ? QUuid()
        : organization.isNull() ? parent : QUuid(collectionForGroup(parent).value("id").toString());
    const auto source = folderPath(folders, remoteId);
    const auto prefix = source + '/';
    if (parent == id || (!parentId.isNull() && folderPath(folders, parentId).startsWith(prefix))) {
        throw BitwardenCliError(QObject::tr("A Bitwarden folder cannot be moved into itself or one of its subfolders."));
    }
    if (source == target) {
        return;
    }
    QSet<QString> outsidePaths;
    QList<BitwardenCli::FolderEdit> edits{{remoteId, source, target}};
    const bool moveSubfolders = countFolderPath(folders, source) == 1;
    for (const auto& value : folders) {
        const auto folder = value.toObject();
        const QUuid folderId(folder.value("id").toString());
        const auto path = folder.value("name").toString();
        if (folderId.isNull() || folderId == remoteId) {
            continue;
        }
        if (moveSubfolders && path.startsWith(prefix)) {
            if (!organization.isNull() && !folder.value("canRename").toBool()) {
                throw BitwardenCliError(QObject::tr("You cannot rename all subcollections of this Bitwarden collection."));
            }
            edits.append({folderId, path, target + path.mid(source.size())});
        } else {
            outsidePaths.insert(path);
        }
    }
    QSet<QString> newPaths;
    for (const auto& edit : edits) {
        if (outsidePaths.contains(edit.newPath) || newPaths.contains(edit.newPath)) {
            throw BitwardenCliError(QObject::tr("A Bitwarden folder with this path already exists."),
                                   BitwardenCliError::Reason::Conflict);
        }
        newPaths.insert(edit.newPath);
    }
    for (const auto& path : outsidePaths) {
        if (path.startsWith(target + '/')) {
            throw BitwardenCliError(QObject::tr("The destination already has Bitwarden subfolders."),
                                   BitwardenCliError::Reason::Conflict);
        }
    }
    auto writes = m_folderWrites;
    writes.append({QUuid::createUuid(), parentId, {}, edits, false, {}, organization});
    storeFolderWrites(std::move(writes));
    if (!organization.isNull()) {
        return;
    }
    projectFolderWrites();
    reconcileGroups(database);
}

void BitwardenSession::queueFolderDelete(Database& database, const QUuid& id)
{
    if (!m_folderQueueError.isEmpty()) {
        throw BitwardenCliError(m_folderQueueError);
    }
    if (!canDeleteFolder(id)) {
        throw BitwardenCliError(QObject::tr("The selected Bitwarden folder is missing or ambiguous."));
    }
    auto writes = m_folderWrites;
    writes.append({QUuid::createUuid(), {}, folderPath(m_folders, id), {}, false, id, {}});
    storeFolderWrites(std::move(writes));
    projectFolderWrites();
    reconcileGroups(database);
}

void BitwardenSession::projectFolderWrites()
{
    m_folders = m_confirmedFolders;
    m_pendingFolderAliases.clear();
    for (const auto& write : m_folderWrites) {
        if (!write.organizationId.isNull()) {
            continue;
        }
        if (!write.deleteId.isNull()) {
            removeFolder(m_folders, write.deleteId);
            continue;
        }
        if (!write.edits.isEmpty()) {
            for (const auto& edit : write.edits) {
                replaceFolder(m_folders, folderRow(edit.id, edit.newPath));
            }
            continue;
        }
        bool matched = false;
        if (write.attempted && countFolderPath(m_folders, write.path) == 1) {
            // A previous run may have written the folder without receiving the server's reply.
            for (qsizetype i = 0; i < m_folders.size(); ++i) {
                const auto folder = m_folders.at(i).toObject();
                const QUuid existing(folder.value("id").toString());
                if (!existing.isNull() && !isPendingFolder(existing) && folder.value("name") == write.path) {
                    m_pendingFolderAliases.insert(existing, write.id);
                    m_folders.replace(i, folderRow(write.id, write.path));
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            m_folders.append(folderRow(write.id, write.path));
        }
    }
}

std::optional<BitwardenSession::FolderWrite> BitwardenSession::beginFolderWrite()
{
    if (!m_connected || !hasPendingFolderWrites()) {
        return std::nullopt;
    }
    auto write = m_folderWrites.first();
    if (!write.attempted && write.isCreate()) {
        auto writes = m_folderWrites;
        writes.first().attempted = true;
        storeFolderWrites(std::move(writes));
    }
    return write;
}

QList<QJsonObject> BitwardenSession::flushFolderWrite(const FolderWrite& write)
{
    if (!write.organizationId.isNull()) {
        if (write.isCreate()) {
            return {m_cli.createCollection(write.organizationId, write.parent, write.path, write.attempted)};
        }
        return m_cli.editCollections(write.organizationId, write.edits, write.parent);
    }
    if (!write.deleteId.isNull()) {
        m_cli.deleteFolder(write.deleteId, write.path);
        return {};
    }
    if (write.isCreate()) {
        return {m_cli.createFolder(write.parent, write.path, write.attempted)};
    }
    return m_cli.editFolders(write.edits, write.parent);
}

void BitwardenSession::applyFolderWrite(Database& database,
                                       const FolderWrite& write,
                                       const QList<QJsonObject>& result)
{
    if (!hasPendingFolderWrites() || m_folderWrites.first().id != write.id
        || (write.deleteId.isNull() && result.isEmpty())) {
        throw BitwardenCliError(QObject::tr("Could not confirm the pending Bitwarden folder change."));
    }
    auto writes = m_folderWrites;
    writes.removeFirst();
    if (!write.organizationId.isNull()) {
        for (const auto& collection : result) {
            if (QUuid(collection.value("organizationId").toString()) != write.organizationId
                || QUuid(collection.value("id").toString()).isNull()) {
                throw BitwardenCliError(QObject::tr("Could not confirm the pending Bitwarden folder change."));
            }
        }
        storeFolderWrites(std::move(writes));
        for (const auto& collection : result) {
            auto current = collectionForGroup(collectionGroupId(write.organizationId,
                                                               QUuid(collection.value("id").toString())));
            for (auto field = collection.constBegin(); field != collection.constEnd(); ++field) {
                current.insert(field.key(), field.value());
            }
            replaceFolder(m_collections, current);
        }
        rebuildCollectionIndex();
        reconcileOrganizationCollections(database, write.organizationId);
        m_needsInitialSync = true;
        return;
    }
    QUuid confirmedId;
    if (write.isCreate()) {
        confirmedId = QUuid(result.first().value("id").toString());
        if (confirmedId.isNull() || confirmedId == m_rootId) {
            throw BitwardenCliError(QObject::tr("Could not confirm the pending Bitwarden folder change."));
        }
        for (auto& next : writes) {
            if (next.parent == write.id) {
                next.parent = confirmedId;
            }
            if (next.deleteId == write.id) {
                next.deleteId = confirmedId;
            }
            for (auto& edit : next.edits) {
                if (edit.id == write.id) {
                    edit.id = confirmedId;
                }
            }
        }
    }
    storeFolderWrites(std::move(writes));
    if (!write.deleteId.isNull()) {
        removeFolder(m_confirmedFolders, write.deleteId);
        m_needsInitialSync = true;
    }
    for (const auto& folder : result) {
        replaceFolder(m_confirmedFolders, folder);
    }
    if (write.isCreate()) {
        auto* personalVault = database.rootGroup()->findGroupByUuid(m_rootId);
        if (auto* group = personalVault->findGroupByUuid(write.id)) {
            if (!personalVault->findGroupByUuid(confirmedId)) {
                group->setEmitModified(false);
                group->setUuid(confirmedId);
                group->setEmitModified(true);
            }
        }
    }
    projectFolderWrites();
    reconcileGroups(database);
}

void BitwardenSession::rejectFolderWrite(const FolderWrite& write, BitwardenCliError::Reason reason)
{
    if (!write.attempted && reason != BitwardenCliError::Reason::WriteUncertain && hasPendingFolderWrites()
        && m_folderWrites.first().id == write.id && write.isCreate()) {
        auto writes = m_folderWrites;
        writes.first().attempted = false;
        storeFolderWrites(std::move(writes));
    }
}

void BitwardenSession::discardPendingFolderWrites(Database& database)
{
    if (database.isModified() || !m_connected || !hasPendingFolderWrites()) {
        throw BitwardenCliError(QObject::tr("Save or discard entry changes before discarding pending folder changes."));
    }
    QSet<QUuid> removedIds;
    for (const auto& write : m_folderWrites) {
        if (!write.deleteId.isNull()) {
            removedIds.insert(write.deleteId);
        }
    }
    const auto aliases = m_pendingFolderAliases;
    storeFolderWrites({});
    auto* root = database.rootGroup()->findGroupByUuid(m_rootId);
    for (auto alias = aliases.cbegin(); alias != aliases.cend(); ++alias) {
        if (removedIds.contains(alias.value())) {
            removedIds.insert(alias.key());
        }
        if (auto* group = root->findGroupByUuid(alias.value())) {
            if (!root->findGroupByUuid(alias.key())) {
                group->setEmitModified(false);
                group->setUuid(alias.key());
                group->setEmitModified(true);
            }
        }
    }
    projectFolderWrites();
    reconcileGroups(database, removedIds);
}

void BitwardenSession::reconcileGroups(Database& database, const QSet<QUuid>& restoredFolderIds)
{
    // Folder changes are persisted separately. Keep entry edits dirty and still notify the tree models.
    const auto emitModified = database.modifiedSignalEnabled();
    database.setEmitModified(false);
    const auto restoreModified = qScopeGuard([&database, emitModified] { database.setEmitModified(emitModified); });
    auto* root = database.rootGroup()->findGroupByUuid(m_rootId);
    Q_ASSERT(root);
    QHash<QUuid, Group*> groups;
    for (auto* group : root->groupsRecursive(false)) {
        groups.insert(group->uuid(), group);
    }
    QHash<QString, Group*> paths;
    QSet<QUuid> retained;
    for (const auto& folder : sortedFolders(m_folders)) {
        const QUuid id(folder.value("id").toString());
        const auto path = folder.value("name").toString();
        if (id.isNull() || id == m_rootId || retained.contains(id)) {
            continue;
        }
        retained.insert(id);
        const auto separator = path.lastIndexOf('/');
        auto* parent = separator > 0 ? paths.value(path.left(separator), root) : root;
        auto* group = groups.take(id);
        if (!group) {
            group = new Group();
        }
        group->setUuid(id);
        group->setName(parent == root ? path : path.mid(separator + 1));
        if (group->parentGroup() != parent) {
            group->setParent(parent, -1, false);
        }
        if (!paths.contains(path)) {
            paths.insert(path, group);
        }
    }
    // When a folder disappears, direct entries go to the vault root. Retained subfolders have already been reparented.
    QSet<Group*> obsolete;
    for (auto* old : groups) {
        for (auto* entry : old->entries()) {
            entry->setGroup(root, false);
        }
        if (!groups.contains(old->parentGroup()->uuid())) {
            obsolete.insert(old);
        }
    }
    qDeleteAll(obsolete);

    if (!restoredFolderIds.isEmpty()) {
        // When a deletion is discarded, restore the confirmed assignments from the cached items.
        for (const auto& value : m_items) {
            const auto item = value.toObject();
            const QUuid folderId(item.value("folderId").toString());
            if (restoredFolderIds.contains(folderId)) {
                auto* destination = root->findGroupByUuid(folderId);
                auto* entry = root->findEntryByUuid(QUuid(item.value("id").toString()));
                if (destination && entry && entry->group() == root) {
                    entry->setGroup(destination, false);
                }
            }
        }
    }
}

void BitwardenSession::reconcileOrganizationCollections(Database& database, const QUuid& organizationId)
{
    auto* vault = database.rootGroup()->findGroupByUuid(organizationGroupId(organizationId, "organization"));
    if (!vault) {
        return;
    }
    const auto emitModified = database.modifiedSignalEnabled();
    database.setEmitModified(false);
    const auto restoreModified = qScopeGuard([&database, emitModified] { database.setEmitModified(emitModified); });
    QHash<QString, Group*> paths;
    for (const auto& collection : sortedFolders(organizationCollections(m_collections, organizationId))) {
        const QUuid id(collection.value("id").toString());
        const auto path = collection.value("name").toString();
        if (id.isNull() || !validFolderPath(path)) {
            continue;
        }
        const auto separator = path.lastIndexOf('/');
        auto* parent = separator > 0 ? paths.value(path.left(separator), vault) : vault;
        const auto groupId = collectionGroupId(organizationId, id);
        auto* group = vault->findGroupByUuid(groupId);
        if (!group) {
            group = new Group();
            group->setUuid(groupId);
            group->setProperty("bitwardenCollection", true);
        }
        group->setName(parent == vault ? path : path.mid(separator + 1));
        if (group->parentGroup() != parent) {
            group->setParent(parent, -1, false);
        }
        if (!paths.contains(path)) {
            paths.insert(path, group);
        }
    }
}
QSharedPointer<Database> BitwardenSession::makeDatabase(const VaultSnapshot& snapshot) const
{
    auto database = QSharedPointer<Database>::create();
    database->setLiteralEntryValues(true);
    database->setEmitModified(false);
    database->metadata()->setName(m_name);
    database->metadata()->setRecycleBinEnabled(false);
    auto* container = database->rootGroup();
    container->setUuid(m_containerId);
    container->setProperty("bitwardenVaultRoots", true);
    auto* root = new Group();
    root->setUuid(m_rootId);
    root->setName(QCoreApplication::translate("BitwardenSession", "Private"));
    root->setParent(container);

    const auto organizationGroups = buildOrganizationGroups(container, snapshot);

    QHash<QString, Group*> paths;
    QHash<QUuid, Group*> folderIds;
    for (const auto& folder : sortedFolders(snapshot.folders)) {
        const auto name = folder.value("name").toString();
        const QUuid id(folder.value("id").toString());
        if (id.isNull() || id == m_rootId || folderIds.contains(id)) {
            continue;
        }
        auto* group = new Group();
        group->setUuid(id);
        const auto separator = name.lastIndexOf('/');
        auto* parent = separator > 0 ? paths.value(name.left(separator), root) : root;
        group->setName(parent == root ? name : name.mid(separator + 1));
        group->setParent(parent);
        folderIds.insert(id, group);
        if (!paths.contains(name)) {
            paths.insert(name, group);
        }
    }

    QSet<QUuid> ids;
    for (const auto& value : snapshot.items) {
        const auto item = value.toObject();
        if (!visibleItem(item)) {
            continue;
        }
        const QUuid id(item.value("id").toString());
        if (id.isNull() || ids.contains(id)) {
            throw BitwardenCliError(QObject::tr("Bitwarden returned an invalid or duplicate entry ID."));
        }
        const auto organization = item.value("organizationId").toString();
        const QUuid organizationId(organization);
        auto* organizationVault = organizationGroups.vaults.value(organizationId);
        if (!organization.isEmpty() && !organizationVault) {
            throw BitwardenCliError(QObject::tr("Bitwarden returned an invalid organization ID."));
        }
        ids.insert(id);
        auto* entry = new Entry();
        entry->setUuid(id);
        entry->setTitle(item.value("name").toString());
        entry->setNotes(item.value("notes").toString());
        if (item.value("type").toInt() == 1) {
            setLoginFields(*entry, item);
        } else {
            entry->setAutoTypeEnabled(false);
        }
        if (!organizationVault) {
            const QUuid folderId(item.value("folderId").toString());
            entry->setGroup(folderIds.value(m_pendingFolderAliases.value(folderId, folderId), root));
        } else {
            const auto collections = organizationGroups.collections.value(organizationId);
            QVariantList memberships;
            QSet<QUuid> added;
            for (const auto& value : item.value("collectionIds").toArray()) {
                if (const auto* collection = collections.value(QUuid(value.toString())); collection
                    && !added.contains(collection->uuid())) {
                    memberships.append(collection->uuid());
                    added.insert(collection->uuid());
                }
            }
            entry->setProperty("bitwardenCollectionGroups", memberships);
            entry->setGroup(organizationVault);
        }
    }

    database->setEmitModified(true);
    // The saved signal refreshes the username and custom attribute indexes.
    database->markAsClean();
    database->updateTagList();
    return database;
}

QList<BitwardenSession::Edit> BitwardenSession::prepareSave(const Database& database) const
{
    auto expected = makeDatabase();
    const auto expectedGroups = expected->rootGroup()->groupsRecursive(true);
    const auto groups = database.rootGroup()->groupsRecursive(true);
    if (expectedGroups.size() != groups.size()) {
        throw unsupportedChange();
    }
    for (auto* oldGroup : expectedGroups) {
        const auto* group = database.rootGroup()->findGroupByUuid(oldGroup->uuid());
        if (!group) {
            throw unsupportedChange();
        }
        normalizeTimes(*oldGroup, *group);
        if (!sameFolder(*oldGroup, *group)) {
            throw unsupportedChange();
        }
    }

    QList<Edit> edits;
    QSet<QUuid> knownEntries;
    for (qsizetype index = 0; index < m_items.size(); ++index) {
        const auto item = m_items.at(index).toObject();
        if (!visibleItem(item)) {
            continue;
        }
        const QUuid id(item.value("id").toString());
        knownEntries.insert(id);
        auto* oldEntry = expected->rootGroup()->findEntryByUuid(id);
        const auto* entry = database.rootGroup()->findEntryByUuid(id);
        if (!entry || !oldEntry) {
            throw unsupportedChange();
        }
        auto updated = updatedLogin(*entry, *oldEntry, item, m_fullEditing);
        if (oldEntry->group()->uuid() != entry->group()->uuid()) {
            const auto destination = entry->group()->uuid();
            if (!m_fullEditing || !personalLogin(item) || folderScopeId(destination) != m_rootId) {
                throw unsupportedChange();
            }
            if (isPendingFolder(entry->group()->uuid())) {
                throw BitwardenCliError(QObject::tr("Synchronize the new Bitwarden folder before saving entries in it."));
            }
            updated.insert("folderId", folderFor(*entry, m_rootId));
        }
        oldEntry->setPreviousParentGroupUuid(entry->previousParentGroupUuid());
        normalizeTimes(*oldEntry, *entry);
        if (!oldEntry->equals(entry, CompareVault)) {
            throw unsupportedChange();
        }
        const auto move = m_stagedEntryMoves.constFind(id);
        if (!updated.isEmpty() || move != m_stagedEntryMoves.constEnd()) {
            const auto revision = item.value("revisionDate").toString();
            if (revision.isEmpty()) {
                throw BitwardenCliError(QObject::tr("Bitwarden did not provide a revision for the edited entry."));
            }
            updated.insert("id", item.value("id"));
            edits.append({index,
                          updated,
                          revision,
                          {},
                          move == m_stagedEntryMoves.constEnd() ? std::nullopt : std::optional<ItemMove>(*move)});
        }
    }
    for (const auto* entry : database.rootGroup()->entriesRecursive()) {
        if (knownEntries.contains(entry->uuid())) {
            continue;
        }
        if (m_uncertainCreates.contains(entry->uuid())) {
            throw BitwardenCliError(QObject::tr("Bitwarden did not confirm this creation. Check the server before trying again."));
        }
        const auto group = entry->group()->uuid();
        if (isPendingFolder(group)) {
            throw BitwardenCliError(QObject::tr("Synchronize the new Bitwarden folder before saving entries in it."));
        }
        if (!canCreateInGroup(group)) {
            throw unsupportedChange();
        }
        auto item = newLogin(*entry, m_rootId);
        const auto collection = collectionForGroup(group);
        if (!collection.isEmpty()) {
            item.insert("folderId", QJsonValue::Null);
            item.insert("organizationId", collection.value("organizationId"));
            item.insert("collectionIds", QJsonArray{collection.value("id")});
        }
        edits.append({-1, item, {}, entry->uuid(), std::nullopt});
    }
    return edits;
}

BitwardenSession::SaveResult BitwardenSession::save(const QList<Edit>& edits)
{
    SaveResult result;
    const auto rememberPlacement = [&result](const QUuid& id, const QJsonObject& saved) {
        if (!saved.value("organizationId").toString().isEmpty()) {
            result.savedItems.insert(id,
                                     {{"organizationId", saved.value("organizationId")},
                                      {"collectionIds", saved.value("collectionIds")},
                                      {"viewPassword", saved.value("viewPassword")}});
        }
    };
    for (const auto& edit : edits) {
        try {
            if (!edit.draftId.isNull()) {
                const auto saved = m_cli.createItem(edit.item);
                const QUuid id(saved.value("id").toString());
                m_items.append(saved);
                result.createdIds.insert(edit.draftId, id);
                rememberPlacement(id, saved);
            } else {
                const auto id = edit.item.value("id").toString();
                auto revision = edit.revision;
                if (edit.item.size() > 1) {
                    const auto saved = m_cli.editItem(id, edit.item, revision);
                    m_items.replace(edit.index, saved);
                    revision = saved.value("revisionDate").toString();
                }
                if (edit.move) {
                    const auto& move = *edit.move;
                    const auto saved = m_cli.moveItem(id,
                                                      revision,
                                                      move.sourceOrganization,
                                                      move.destinationOrganization,
                                                      move.sourceCollection,
                                                      move.destinationCollection);
                    m_items.replace(edit.index, saved);
                    rememberPlacement(QUuid(id), saved);
                }
            }
        } catch (const BitwardenCliError& error) {
            if (!edit.draftId.isNull()) {
                m_uncertainCreates.insert(edit.draftId);
            }
            result.error = error.message();
            break;
        }
    }
    return result;
}

void BitwardenSession::applySavedItemPlacements(Database& database, const SaveResult& result)
{
    if (result.savedItems.isEmpty()) {
        return;
    }
    const auto emitModified = database.modifiedSignalEnabled();
    database.setEmitModified(false);
    const auto restoreModified = qScopeGuard([&database, emitModified] { database.setEmitModified(emitModified); });
    auto* root = database.rootGroup();
    for (auto saved = result.savedItems.constBegin(); saved != result.savedItems.constEnd(); ++saved) {
        const QUuid organization(saved->value("organizationId").toString());
        auto* vault = root->findGroupByUuid(organizationGroupId(organization, "organization"));
        auto* entry = root->findEntryByUuid(saved.key());
        if (!vault || !entry) {
            continue;
        }
        QVariantList memberships;
        for (const auto& value : saved->value("collectionIds").toArray()) {
            const QUuid collection(value.toString());
            const auto group = collectionGroupId(organization, collection);
            if (!collection.isNull() && m_collectionIndexes.contains(group)) {
                memberships.append(group);
            }
        }
        if (!saved->value("viewPassword").toBool()) {
            entry->setPassword({});
            entry->setTotp({});
            entry->setProperty("bitwardenPasskeys", {});
            for (const auto& name : entry->attributes()->customKeys()) {
                if (entry->attributes()->isProtected(name)) {
                    entry->attributes()->remove(name);
                }
            }
        }
        entry->setProperty("bitwardenCollectionGroups", memberships);
        entry->setGroup(vault, false);
        m_stagedEntryMoves.remove(saved.key());
    }
}
