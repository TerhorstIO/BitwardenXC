/*
 * Copyright (C) 2026 BitwardenXC contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef BITWARDENXC_SESSION_H
#define BITWARDENXC_SESSION_H

#include "remote/BitwardenCli.h"
#include "remote/BitwardenFolderJournal.h"

#include <QList>
#include <QHash>
#include <QSet>
#include <QSharedPointer>
#include <QUuid>

#include <functional>

class Database;

class BitwardenSession
{
public:
    enum class OpenStage
    {
        CheckingProfile = 1,
        OpeningCache,
        Authenticating,
        Synchronizing,
        ReadingVault,
        PreparingView
    };
    using OpenProgress = std::function<void(OpenStage)>;
    using VaultSnapshot = BitwardenCli::VaultSnapshot;

    struct ItemMove
    {
        QUuid sourceOrganization;
        QUuid destinationOrganization;
        QUuid sourceCollection;
        QUuid destinationCollection;
    };

    struct Edit
    {
        qsizetype index;
        QJsonObject item;
        QString revision;
        QUuid draftId;
        std::optional<ItemMove> move;
    };

    struct SaveResult
    {
        QHash<QUuid, QUuid> createdIds;
        QHash<QUuid, QJsonObject> savedItems;
        QString error;
    };

    struct FolderWrite
    {
        QUuid id;
        QUuid parent;
        QString path;
        QList<BitwardenCli::FolderEdit> edits;
        bool attempted = false;
        QUuid deleteId;
        QUuid organizationId;

        bool isCreate() const
        {
            return deleteId.isNull() && edits.isEmpty();
        }
    };

    BitwardenSession(QString executable, QUrl server, QString email);

    void connect(QByteArray password,
                 QString code = {},
                 QString clientId = {},
                 QByteArray clientSecret = {},
                 const OpenProgress& progress = {});
    void unlock(QByteArray password, const OpenProgress& progress = {});
    bool needsInitialSync() const;
    QUuid personalRootId() const;
    VaultSnapshot fetchSync(bool force, const std::function<bool()>& canceled = {});
    QSharedPointer<Database> applySync(VaultSnapshot snapshot);
    void lock();
    SaveResult save(const QList<Edit>& edits);
    bool canCreateInGroup(const QUuid& group) const;
    bool canMoveEntry(const QUuid& entry, const QUuid& sourceView, const QUuid& destination) const;
    void stageEntryMove(const QUuid& entry, const QUuid& sourceView, const QUuid& destination);
    void clearStagedEntryMove(const QUuid& entry);
    void applySavedItemPlacements(Database& database, const SaveResult& result);
    QUuid queueFolderCreate(Database& database, const QUuid& parent, const QString& name);
    void queueFolderUpdate(Database& database, const QUuid& id, const QUuid& parent, const QString& name);
    void queueFolderDelete(Database& database, const QUuid& id);
    bool hasPendingFolderWrites() const;
    QString folderQueueError() const;
    bool isPendingFolder(const QUuid& id) const;
    bool canEditFolder(const QUuid& id) const;
    bool canUseFolderAsParent(const QUuid& id) const;
    bool canCreateFolder(const QUuid& id) const;
    bool canDeleteFolder(const QUuid& id) const;
    QUuid folderScopeId(const QUuid& id) const;
    std::optional<FolderWrite> beginFolderWrite();
    QList<QJsonObject> flushFolderWrite(const FolderWrite& write);
    void applyFolderWrite(Database& database, const FolderWrite& write, const QList<QJsonObject>& result);
    void rejectFolderWrite(const FolderWrite& write, BitwardenCliError::Reason reason);
    void discardPendingFolderWrites(Database& database);

    QSharedPointer<Database> makeDatabase() const;
    bool canEdit(const QUuid& id) const;
    bool isDraft(const QUuid& id) const;
    bool canCreate() const;
    bool supportsFullEditing() const;
    static QString stageText(OpenStage stage);
    static bool isEditableFieldName(const QString& name);
    QList<Edit> prepareSave(const Database& database) const;

private:
    bool openCachedVault(const QByteArray& password, const OpenProgress& progress);
    void loadVault(bool synchronize, bool force, const OpenProgress& progress);
    void setVault(VaultSnapshot snapshot, bool needsInitialSync);
    void loadFolderWrites(const QByteArray& password);
    void restoreFolderWrites(const QJsonArray& records);
    void storeFolderWrites(QList<FolderWrite> writes);
    void projectFolderWrites();
    void reconcileGroups(Database& database, const QSet<QUuid>& restoredFolderIds = {});
    void reconcileOrganizationCollections(Database& database, const QUuid& organizationId);
    void rebuildCollectionIndex();
    QJsonObject collectionForGroup(const QUuid& id) const;
    QJsonObject organizationForGroup(const QUuid& id) const;
    bool hasPendingCollectionWrite(const QUuid& organizationId) const;
    std::optional<ItemMove> entryMove(const QUuid& entry, const QUuid& sourceView, const QUuid& destination) const;
    QString folderPathForWrite(const QUuid& parent, const QString& name) const;
    QSharedPointer<Database> makeDatabase(const VaultSnapshot& snapshot) const;

    BitwardenCli m_cli;
    BitwardenFolderJournal m_folderJournal;
    QString m_name;
    QUuid m_containerId = QUuid::createUuid();
    QUuid m_rootId = QUuid::createUuid();
    QList<FolderWrite> m_folderWrites;
    QString m_folderQueueError;
    QJsonArray m_confirmedFolders;
    QHash<QUuid, QUuid> m_pendingFolderAliases;
    QJsonArray m_folders;
    QJsonArray m_items;
    QJsonArray m_organizations;
    QJsonArray m_collections;
    QHash<QUuid, qsizetype> m_collectionIndexes;
    QHash<QUuid, ItemMove> m_stagedEntryMoves;
    QSet<QUuid> m_uncertainCreates;
    bool m_fullEditing = false;
    bool m_connected = false;
    bool m_needsInitialSync = false;
};

#endif
