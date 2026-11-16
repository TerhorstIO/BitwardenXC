/*
 * Copyright (C) 2026 BitwardenXC contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef BITWARDENXC_FOLDERJOURNAL_H
#define BITWARDENXC_FOLDERJOURNAL_H

#include <QByteArray>
#include <QJsonArray>
#include <QString>

class BitwardenFolderJournal
{
public:
    BitwardenFolderJournal() = default;
    ~BitwardenFolderJournal();

    QJsonArray unlock(const QString& path, const QByteArray& masterPassword);
    void save(const QJsonArray& operations);
    void lock();

private:
    Q_DISABLE_COPY_MOVE(BitwardenFolderJournal)

    QString m_path;
    QByteArray m_salt;
    QByteArray m_key;
};

#endif
