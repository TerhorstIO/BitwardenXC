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
            && sameOrder(old.children(), current.children()) && sameOrder(old.entries(), current.entries());
    }

    BitwardenCliError unsupportedChange()
    {
        return BitwardenCliError(QObject::tr("BitwardenXC can save the title and notes of existing personal logins."));
    }

    QJsonObject updatedLogin(const Entry& entry, Entry& expected, const QJsonObject& item)
    {
        if (!personalLogin(item)) {
            return {};
        }
        QJsonObject fields;
        if (entry.title() != expected.title()) {
            expected.setTitle(entry.title());
            fields.insert("name", entry.title());
        }
        if (entry.notes() != expected.notes()) {
            expected.setNotes(entry.notes());
            fields.insert("notes", entry.notes());
        }
        return fields;
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
}

void BitwardenSession::lock()
{
    m_items = {};
    m_folders = {};
    m_cli.lock();
}

bool BitwardenSession::canEdit(const QUuid& id) const
{
    for (const auto& value : m_items) {
        const auto item = value.toObject();
        if (QUuid(item.value("id").toString()) == id) {
            return visibleItem(item) && personalLogin(item);
        }
    }
    return false;
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
    for (qsizetype index = 0; index < m_items.size(); ++index) {
        const auto item = m_items.at(index).toObject();
        if (!visibleItem(item)) {
            continue;
        }
        const QUuid id(item.value("id").toString());
        auto* oldEntry = expected->rootGroup()->findEntryByUuid(id);
        const auto* entry = database.rootGroup()->findEntryByUuid(id);
        if (!entry || !oldEntry) {
            throw unsupportedChange();
        }
        auto updated = updatedLogin(*entry, *oldEntry, item);
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
            edits.append({index, updated, revision});
        }
    }
    return edits;
}

void BitwardenSession::save(const QList<Edit>& edits)
{
    for (const auto& edit : edits) {
        const auto id = edit.item.value("id").toString();
        const auto saved = m_cli.editItem(id, edit.item, edit.revision);
        m_items.replace(edit.index, saved);
    }
}
