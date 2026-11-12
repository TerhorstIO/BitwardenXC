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

class Database;

class BitwardenSession
{
public:
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

    void connect(QByteArray password, QString code = {}, QString clientId = {}, QByteArray clientSecret = {});
    void unlock(QByteArray password);
    void sync();
    void lock();
    SaveResult save(const QList<Edit>& edits);

    QSharedPointer<Database> makeDatabase() const;
    bool canEdit(const QUuid& id) const;
    bool isDraft(const QUuid& id) const;
    bool canCreate() const;
    bool supportsFullEditing() const;
    static bool isEditableFieldName(const QString& name);
    QList<Edit> prepareSave(const Database& database) const;

private:
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
