/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
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

#include "TestUpdateCheck.h"
#include "crypto/Crypto.h"
#include "networking/UpdateChecker.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QTest>

QTEST_GUILESS_MAIN(TestUpdateCheck)

void TestUpdateCheck::initTestCase()
{
    QVERIFY(Crypto::init());
    QLocale::setDefault(QLocale::c());
}

void TestUpdateCheck::testCompareVersion()
{
    // No upgrade
    QCOMPARE(UpdateChecker::compareVersions(QString("2.3.0"), QString("2.3.0")), false);

    // First digit upgrade
    QCOMPARE(UpdateChecker::compareVersions(QString("2.4.0"), QString("3.0.0")), true);
    QCOMPARE(UpdateChecker::compareVersions(QString("3.0.0"), QString("2.4.0")), false);

    // Second digit upgrade
    QCOMPARE(UpdateChecker::compareVersions(QString("2.3.4"), QString("2.4.0")), true);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.4.0"), QString("2.3.4")), false);

    // Third digit upgrade
    QCOMPARE(UpdateChecker::compareVersions(QString("2.3.0"), QString("2.3.1")), true);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.3.1"), QString("2.3.0")), false);

    QVERIFY(UpdateChecker::compareVersions(QString("2.8.999"), QString("2.8.1000")));
    QVERIFY(!UpdateChecker::compareVersions(QString("2.8.1000"), QString("2.8.999")));

    // Stable releases use exactly three numeric components.
    QCOMPARE(UpdateChecker::compareVersions(QString("2.3.0"), QString("2.3.1-beta1")), false);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.3.0-beta1"), QString("2.3.0")), false);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.3.4-snapshot"), QString("2.4.0")), false);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.4.0"), QString("invalid")), false);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.4.0"), QString("")), false);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.4.0"), QString("2.5.00")), false);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.4.0"), QString("2.5.0.1")), false);
    QCOMPARE(UpdateChecker::compareVersions(QString("2.4.0"), QString("2.5.0\n")), false);
}

void TestUpdateCheck::testParseRelease()
{
    const auto releaseAsset = [](const QString& name) {
        return QJsonObject{{"name", name},
                           {"state", "uploaded"},
                           {"size", 1000},
                           {"browser_download_url", "https://example.invalid/untrusted-download"}};
    };
    const auto installer = releaseAsset(QString("BitwardenXC-Windows-x64.msi"));
    const auto portable = releaseAsset(QString("BitwardenXC-Windows-x64.zip"));
    QJsonObject response{{"tag_name", "2.8.2913"},
                         {"draft", false},
                         {"prerelease", false},
                         {"assets", QJsonArray{installer, portable, releaseAsset(QString("SHA256SUMS"))}}};
    const auto release = UpdateChecker::parseRelease(response);
    QVERIFY(release.has_value());
    QCOMPARE(release->version, QString("2.8.2913"));
    QCOMPARE(release->page, QUrl(QString("https://github.com/TerhorstIO/BitwardenXC/releases/tag/2.8.2913")));
    const QString downloads = "https://github.com/TerhorstIO/BitwardenXC/releases/download/2.8.2913/";
    QCOMPARE(release->installer, QUrl(downloads + "BitwardenXC-Windows-x64.msi"));
    QCOMPARE(release->portableZip, QUrl(downloads + "BitwardenXC-Windows-x64.zip"));

    response.insert("assets", QJsonArray{portable});
    const auto portableOnly = UpdateChecker::parseRelease(response);
    QVERIFY(portableOnly.has_value());
    QVERIFY(portableOnly->installer.isEmpty());

    response.insert("draft", true);
    QVERIFY(!UpdateChecker::parseRelease(response));
    response.insert("draft", false);
    response.insert("prerelease", true);
    QVERIFY(!UpdateChecker::parseRelease(response));
    response.insert("prerelease", false);

    response.insert("tag_name", "build-410fa30e5dfc900541d01d90fa74a1343a5ef5d0");
    QVERIFY(!UpdateChecker::parseRelease(response));
    response.insert("tag_name", "2.8.2913/../../outside");
    QVERIFY(!UpdateChecker::parseRelease(response));
    response.insert("tag_name", "2.8.2913");
    response.insert("assets", QJsonArray{releaseAsset(QString("SHA256SUMS"))});
    QVERIFY(!UpdateChecker::parseRelease(response));

    auto pendingAsset = installer;
    pendingAsset.insert("state", "new");
    response.insert("assets", QJsonArray{pendingAsset});
    QVERIFY(!UpdateChecker::parseRelease(response));
}
