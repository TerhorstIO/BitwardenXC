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

    template <typename Item> bool sameOrder(const QList<Item*>& left, const QList<Item*>& right)
    {
        return std::equal(left.begin(), left.end(), right.begin(), right.end(), [](const Item* a, const Item* b) {
            return a->uuid() == b->uuid();
        });
    }

    bool sameFolder(const Group& old, const Group& current)
    {
        return old.name() == current.name() && old.notes() == current.notes() && old.tags() == current.tags()
            && old.iconNumber() == current.iconNumber() && old.iconUuid() == current.iconUuid()
            && old.timeInfo().equals(current.timeInfo(), CompareVault)
            && old.defaultAutoTypeSequence() == current.defaultAutoTypeSequence()
            && old.autoTypeEnabled() == current.autoTypeEnabled() && old.searchingEnabled() == current.searchingEnabled()
            && old.mergeMode() == current.mergeMode() && *old.customData() == *current.customData()
            && sameOrder(old.children(), current.children());
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

void BitwardenSession::connect(QByteArray password, QString code, QString clientId, QByteArray clientSecret)
{
    const auto wipe = qScopeGuard([&] {
        password.fill('\0');
        code.fill(QChar());
        clientId.fill(QChar());
        clientSecret.fill('\0');
    });
    m_fullEditing = m_cli.supportsFullEditing();
    const auto state = m_cli.status().value("status").toString();
    const auto hasProfile = state == "locked" || state == "unlocked";
    if (hasProfile && (!clientId.isEmpty() || !code.isEmpty())) {
        m_cli.logout();
    }
    if (hasProfile && clientId.isEmpty() && code.isEmpty()) {
        m_cli.unlock(password);
    } else if (!clientId.isEmpty()) {
        m_cli.loginWithApiKey(clientId, clientSecret);
        m_cli.unlock(password);
    } else {
        m_cli.login(password, code);
    }
    sync();
}

void BitwardenSession::sync()
{
    m_cli.sync();
    auto folders = m_cli.listFolders();
    auto items = m_cli.listItems();
    m_folders = std::move(folders);
    m_items = std::move(items);
    m_connected = true;
}

void BitwardenSession::lock()
{
    m_items = {};
    m_folders = {};
    m_connected = false;
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
    auto database = QSharedPointer<Database>::create();
    database->setLiteralEntryValues(true);
    database->setEmitModified(false);
    database->metadata()->setName(m_name);
    database->metadata()->setRecycleBinEnabled(false);
    auto* root = database->rootGroup();
    root->setUuid(m_rootId);
    root->setName(QObject::tr("Vault"));

    QList<QJsonObject> folders;
    for (const auto& value : m_folders) {
        folders.append(value.toObject());
    }
    std::stable_sort(folders.begin(), folders.end(), [](const QJsonObject& left, const QJsonObject& right) {
        return left.value("name").toString().count('/') < right.value("name").toString().count('/');
    });

    QHash<QString, Group*> paths;
    QHash<QUuid, Group*> folderIds;
    for (const auto& folder : folders) {
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
    for (const auto& value : m_items) {
        const auto item = value.toObject();
        if (!visibleItem(item)) {
            continue;
        }
        const QUuid id(item.value("id").toString());
        if (id.isNull() || ids.contains(id)) {
            throw BitwardenCliError(QObject::tr("Bitwarden returned an invalid or duplicate entry ID."));
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
        const QUuid folderId(item.value("folderId").toString());
        entry->setGroup(folderIds.value(folderId, root));
    }

    database->setEmitModified(true);
    database->markAsClean();
    database->updateCommonUsernames();
    database->updateTagList();
    database->updateCustomAttributeKeys();
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
            if (!m_fullEditing || !personalLogin(item)) {
                throw unsupportedChange();
            }
            updated.insert("folderId", folderFor(*entry, m_rootId));
        }
        normalizeTimes(*oldEntry, *entry);
        if (!oldEntry->equals(entry, CompareVault)) {
            throw unsupportedChange();
        }
        if (!updated.isEmpty()) {
            const auto revision = item.value("revisionDate").toString();
            if (revision.isEmpty()) {
                throw BitwardenCliError(QObject::tr("Bitwarden did not provide a revision for the edited entry."));
            }
            updated.insert("id", item.value("id"));
            edits.append({index, updated, revision, {}});
        }
    }
    for (const auto* entry : database.rootGroup()->entriesRecursive()) {
        if (knownEntries.contains(entry->uuid())) {
            continue;
        }
        if (m_uncertainCreates.contains(entry->uuid())) {
            throw BitwardenCliError(QObject::tr("Bitwarden did not confirm this creation. Check the server before trying again."));
        }
        edits.append({-1, newLogin(*entry, m_rootId), {}, entry->uuid()});
    }
    return edits;
}

BitwardenSession::SaveResult BitwardenSession::save(const QList<Edit>& edits)
{
    SaveResult result;
    for (const auto& edit : edits) {
        try {
            if (!edit.draftId.isNull()) {
                const auto saved = m_cli.createItem(edit.item);
                const QUuid id(saved.value("id").toString());
                m_items.append(saved);
                result.createdIds.insert(edit.draftId, id);
            } else {
                const auto id = edit.item.value("id").toString();
                const auto saved = m_cli.editItem(id, edit.item, edit.revision);
                m_items.replace(edit.index, saved);
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
