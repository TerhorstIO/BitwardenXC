/*
 *  Copyright (C) 2025 KeePassXC Team <team@keepassxc.org>
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

#include "UpdateChecker.h"

#include "NetworkManager.h"
#include "config-keepassx.h"
#include "core/Clock.h"
#include "core/Config.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QRegularExpression>
#include <QVersionNumber>

namespace
{
    constexpr qsizetype MaximumReleaseResponseSize = 256 * 1024;
    const auto RepoReleases = QStringLiteral("https://github.com/TerhorstIO/BitwardenXC/releases/");

    QVersionNumber numericVersion(const QString& version)
    {
        qsizetype suffixIndex = 0;
        const auto parsed = QVersionNumber::fromString(version, &suffixIndex);
        if (parsed.segmentCount() != 3 || suffixIndex != version.size() || parsed.toString() != version) {
            return {};
        }
        return parsed;
    }
}

const QString UpdateChecker::ErrorVersion("error");
UpdateChecker* UpdateChecker::m_instance(nullptr);

UpdateChecker::UpdateChecker(QObject* parent)
    : QObject(parent)
    , m_reply(nullptr)
    , m_isManuallyRequested(false)
{
}

UpdateChecker::~UpdateChecker()
{
}

void UpdateChecker::checkForUpdates(bool manuallyRequested)
{
    // An explicit check can use a request started by the background checker.
    if (m_reply) {
        m_isManuallyRequested |= manuallyRequested;
        return;
    }

    const auto nextCheck = config()->get(Config::GUI_CheckForUpdatesNextCheck).toULongLong();
    if (!manuallyRequested && Clock::currentSecondsSinceEpoch() < nextCheck) {
        return;
    }

    m_isManuallyRequested = manuallyRequested;
    m_bytesReceived.clear();

    QNetworkRequest request(QUrl(QStringLiteral("https://api.github.com/repos/TerhorstIO/BitwardenXC/releases/latest")));
    request.setRawHeader("Accept", "application/vnd.github+json");
    request.setRawHeader("User-Agent", "BitwardenXC");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::SameOriginRedirectPolicy);
    request.setTransferTimeout(15000);

    m_reply = getNetMgr()->get(request);

    connect(m_reply, &QNetworkReply::finished, this, &UpdateChecker::fetchFinished);
    connect(m_reply, &QIODevice::readyRead, this, &UpdateChecker::fetchReadyRead);
}

void UpdateChecker::fetchReadyRead()
{
    m_bytesReceived += m_reply->read(MaximumReleaseResponseSize + 1 - m_bytesReceived.size());
    if (m_bytesReceived.size() > MaximumReleaseResponseSize) {
        m_reply->abort();
    }
}

void UpdateChecker::fetchFinished()
{
    const auto success = m_reply->error() == QNetworkReply::NoError
        && m_reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200;
    if (success && m_bytesReceived.size() <= MaximumReleaseResponseSize) {
        m_bytesReceived += m_reply->read(MaximumReleaseResponseSize + 1 - m_bytesReceived.size());
    }
    bool hasNewVersion = false;
    auto version = ErrorVersion;

    m_reply->deleteLater();
    m_reply = nullptr;
    m_release = {};

    if (success && m_bytesReceived.size() <= MaximumReleaseResponseSize) {
        const auto response = QJsonDocument::fromJson(m_bytesReceived).object();
        if (const auto release = parseRelease(response)) {
            m_release = *release;
            version = release->version;
            hasNewVersion = compareVersions(QStringLiteral(KEEPASSXC_VERSION), version);
        } else {
            // Older BitwardenXC releases use a commit SHA as their tag.
            static const QRegularExpression legacyTag(R"(\Abuild-[0-9a-f]{40}\z)");
            if (legacyTag.match(response.value("tag_name").toString()).hasMatch()) {
                version.clear();
            }
        }
    }

    if (version != ErrorVersion) {
        config()->set(Config::GUI_CheckForUpdatesNextCheck, Clock::currentDateTime().addDays(1).toSecsSinceEpoch());
    }

    emit updateCheckFinished(hasNewVersion, version, m_isManuallyRequested);
}

bool UpdateChecker::compareVersions(const QString& localVersion, const QString& remoteVersion)
{
    const auto local = numericVersion(localVersion);
    const auto remote = numericVersion(remoteVersion);
    return !local.isNull() && !remote.isNull() && local < remote;
}

std::optional<UpdateChecker::Release> UpdateChecker::parseRelease(const QJsonObject& response)
{
    const auto version = response.value("tag_name").toString();
    if (numericVersion(version).isNull() || response.value("draft") != QJsonValue(false)
        || response.value("prerelease") != QJsonValue(false)) {
        return std::nullopt;
    }

    Release release{version, QUrl(RepoReleases + "tag/" + version), {}, {}};
    const QString downloads = RepoReleases + "download/" + version + '/';
    for (const auto& value : response.value("assets").toArray()) {
        const auto asset = value.toObject();
        if (asset.value("state").toString() != "uploaded" || asset.value("size").toDouble() <= 0) {
            continue;
        }
        const auto name = asset.value("name").toString();
        // Construct links to known assets on this repository using the validated tag.
        if (name == "BitwardenXC-Windows-x64.msi") {
            release.installer = QUrl(downloads + name);
        } else if (name == "BitwardenXC-Windows-x64.zip") {
            release.portableZip = QUrl(downloads + name);
        }
    }

    if (release.installer.isEmpty() && release.portableZip.isEmpty()) {
        return std::nullopt;
    }
    return release;
}

const UpdateChecker::Release& UpdateChecker::release() const
{
    return m_release;
}

UpdateChecker* UpdateChecker::instance()
{
    if (!m_instance) {
        m_instance = new UpdateChecker();
    }

    return m_instance;
}
