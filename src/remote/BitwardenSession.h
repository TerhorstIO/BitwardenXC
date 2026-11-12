/*
 * Copyright (C) 2026 BitwardenXC contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef BITWARDENXC_SESSION_H
#define BITWARDENXC_SESSION_H

#include "remote/BitwardenCli.h"

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
        Authenticating,
        Synchronizing,
        ReadingVault,
        PreparingView
    };
    using OpenProgress = std::function<void(OpenStage)>;

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

    BitwardenSession(QString executable, QUrl server, QString email);

    void connect(QByteArray password,
                 QString code = {},
                 QString clientId = {},
                 QByteArray clientSecret = {},
                 const OpenProgress& progress = {});
    void unlock(QByteArray password, const OpenProgress& progress = {});
    void sync();
    void lock();
    SaveResult save(const QList<Edit>& edits);

    QSharedPointer<Database> makeDatabase() const;
    bool canEdit(const QUuid& id) const;
    bool isDraft(const QUuid& id) const;
    bool canCreate() const;
    bool supportsFullEditing() const;
    static QString stageText(OpenStage stage);
    static bool isEditableFieldName(const QString& name);
    QList<Edit> prepareSave(const Database& database) const;

private:
    void loadVault(bool synchronize, bool force, const OpenProgress& progress);

    BitwardenCli m_cli;
    QString m_name;
    QUuid m_rootId = QUuid::createUuid();
    QJsonArray m_folders;
    QJsonArray m_items;
    QSet<QUuid> m_uncertainCreates;
    bool m_fullEditing = false;
    bool m_connected = false;
};

#endif
