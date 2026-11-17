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

    struct Edit
    {
        qsizetype index;
        QJsonObject item;
        QString revision;
        QUuid draftId;
    };

    struct SaveResult
    {
        QHash<QUuid, QUuid> createdIds;
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
    VaultSnapshot fetchSync(bool force, const std::function<bool()>& canceled = {});
    QSharedPointer<Database> applySync(VaultSnapshot snapshot);
    void lock();
    SaveResult save(const QList<Edit>& edits);
    QUuid queueFolderCreate(Database& database, const QUuid& parent, const QString& name);
    void queueFolderUpdate(Database& database, const QUuid& id, const QUuid& parent, const QString& name);
    void queueFolderDelete(Database& database, const QUuid& id);
    bool hasPendingFolderWrites() const;
    QString folderQueueError() const;
    bool isPendingFolder(const QUuid& id) const;
    bool canEditFolder(const QUuid& id) const;
    bool canUseFolderAsParent(const QUuid& id) const;
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
    QString folderPathForWrite(const QUuid& parent, const QString& name) const;
    QSharedPointer<Database> makeDatabase(const VaultSnapshot& snapshot) const;

    BitwardenCli m_cli;
    BitwardenFolderJournal m_folderJournal;
    QString m_name;
    QUuid m_rootId = QUuid::createUuid();
    QList<FolderWrite> m_folderWrites;
    QString m_folderQueueError;
    QJsonArray m_confirmedFolders;
    QHash<QUuid, QUuid> m_pendingFolderAliases;
    QJsonArray m_folders;
    QJsonArray m_items;
    QSet<QUuid> m_uncertainCreates;
    bool m_fullEditing = false;
    bool m_connected = false;
    bool m_needsInitialSync = false;
};

#endif
