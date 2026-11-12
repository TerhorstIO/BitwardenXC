/*
 * Copyright (C) 2026 BitwardenXC contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef BITWARDENXC_SESSION_H
#define BITWARDENXC_SESSION_H

#include "remote/BitwardenCli.h"

#include <QList>
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
    };

    BitwardenSession(QString executable, QUrl server, QString email);

    void connect(QByteArray password, QString code = {}, QString clientId = {}, QByteArray clientSecret = {});
    void sync();
    void lock();
    void save(const QList<Edit>& edits);

    QSharedPointer<Database> makeDatabase() const;
    bool canEdit(const QUuid& id) const;
    QList<Edit> prepareSave(const Database& database) const;

private:
    BitwardenCli m_cli;
    QString m_name;
    QUuid m_rootId = QUuid::createUuid();
    QJsonArray m_folders;
    QJsonArray m_items;
};

#endif
