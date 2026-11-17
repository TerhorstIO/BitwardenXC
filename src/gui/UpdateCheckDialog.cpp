/*
 *  Copyright (C) 2019 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "UpdateCheckDialog.h"
#include "ui_UpdateCheckDialog.h"

#include <QPushButton>

#include "core/Config.h"
#include "gui/Icons.h"
#include "networking/UpdateChecker.h"

UpdateCheckDialog::UpdateCheckDialog(QWidget* parent)
    : QDialog(parent)
    , m_ui(new Ui::UpdateCheckDialog())
{
    m_ui->setupUi(this);
    setWindowFlags(Qt::Dialog | Qt::WindowTitleHint | Qt::WindowCloseButtonHint);
    setAttribute(Qt::WA_DeleteOnClose);

    m_ui->iconLabel->setPixmap(icons()->applicationIcon().pixmap(48));

    connect(m_ui->buttonBox, SIGNAL(rejected()), SLOT(close()));
    connect(UpdateChecker::instance(),
            SIGNAL(updateCheckFinished(bool, QString, bool)),
            SLOT(showUpdateCheckResponse(bool, QString)));
}

void UpdateCheckDialog::showUpdateCheckResponse(bool hasUpdate, const QString& version)
{
    m_ui->progressBar->setVisible(false);
    m_ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(tr("Close"));

    setWindowTitle(tr("Software Update"));

    if (version == UpdateChecker::ErrorVersion) {
        m_ui->statusLabel->setText(
            tr("An error occurred when trying to retrieve update information, please try again later."));
    } else if (hasUpdate) {
        const auto& release = updateCheck()->release();
        const auto link = [](const QUrl& url, const QString& text) {
            return QStringLiteral("<a href=\"%1\">%2</a>")
                .arg(QString::fromUtf8(url.toEncoded()).toHtmlEscaped(), text.toHtmlEscaped());
        };
        QStringList links;
        if (!release.installer.isEmpty()) {
            links.append(link(release.installer, tr("Windows installer")));
        }
        if (!release.portableZip.isEmpty()) {
            const auto portableLink = link(release.portableZip, tr("Portable ZIP"));
            if (Config::isPortable()) {
                links.prepend(portableLink);
            } else {
                links.append(portableLink);
            }
        }
        links.append(link(release.page, tr("Release notes")));
        m_ui->statusLabel->setText(tr("<strong>BitwardenXC %1 is available.</strong>").arg(version.toHtmlEscaped())
                                   + "<br/>" + links.join("<br/>"));
    } else {
        m_ui->statusLabel->setText(tr("No newer BitwardenXC release is available."));
    }
}

UpdateCheckDialog::~UpdateCheckDialog()
{
}
