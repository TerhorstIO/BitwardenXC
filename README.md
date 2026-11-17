# BitwardenXC

BitwardenXC is a Windows fork of KeePassXC 2.8.0. Bitwarden and Vaultwarden vaults open in the KeePassXC folder tree, entry table and detail view. The native clipboard shortcuts, including `Ctrl+B` for username and `Ctrl+C` for password, and the KeePassXC Auto-Type engine work on entries in the connected vault.

1. Download `BitwardenXC-Windows-x64.msi` from the [latest release](https://github.com/TerhorstIO/BitwardenXC/releases/latest) and run the installer. For portable use, download `BitwardenXC-Windows-x64.zip`, extract it, and start `BitwardenXC.exe` from that folder. Both packages include `bw.exe`.
2. Choose **Database → Open Bitwarden / Vaultwarden**, then enter your server's HTTPS address, email and master password. For Bitwarden Cloud use `https://vault.bitwarden.com` or `https://vault.bitwarden.eu`.
3. For two-step login, enter an authenticator code if required. The personal API key option signs in via the [Bitwarden CLI API-key flow](https://bitwarden.com/help/personal-api-key/) and still needs your master password to unlock the vault.
4. Create a personal login with **New Entry** or open one in the entry editor. The editor supports title, username, password, primary URL, notes, and text or hidden custom fields. **Advanced** shows TOTP setup and saved passkey details. Passkey details are read-only. Use `Ctrl+S` to write changes to the server and **Database → Sync Bitwarden** to pull changes made on another device.

Enable update checks at startup or choose **Help → Check for Updates** to check the BitwardenXC releases on GitHub. The update dialog links to the installer, portable ZIP, and release notes. Close BitwardenXC before updating. Run the new MSI to update an MSI installation and keep its settings. To update a portable copy, extract the new ZIP over the existing application files and keep the `config` directory. Each release includes `SHA256SUMS` for checking the downloads.

With **Remember previously used databases** enabled, the server address and email appear in **Database → Recent Databases** and on the welcome screen. Select the vault to reuse those details. **Clear history** removes the saved connection details alongside the local database history.

Organizations appear as named roots alongside **Private**, the personal vault. Expand an organization to browse the collections available to your account. Entries can appear in multiple collections, and selecting the organization shows all of its supported entries.

With the required [collection permissions](https://bitwarden.com/help/collection-permissions/), use **Groups → New Group** or **Edit Group** to create, rename, or nest organization collections. Collection changes are sent in the background and appear after the server confirms them. Use **New Entry** to create a login in a writable collection. **Entries → Move to Collection** can transfer a private entry to an organization after confirmation or reassign an organization entry within that organization. Reassigning an entry from a collection keeps its other memberships.

Choose **Groups → New Group** to add a personal folder under the selected group. Use **Groups → Edit Group** to rename it or choose a new parent, or drag the folder onto another folder or **Private** to move it. **Groups → Delete Group** removes the selected folder. Its direct entries go to the vault root, and its subfolders keep their Bitwarden paths. The folder tree updates immediately. BitwardenXC keeps pending changes encrypted locally and sends them to the server in the background. It retries temporary failures while the vault is open. The status icon shows progress and lets you retry manually. Entries can be saved in a new folder after the server assigns it an ID.

The connection dialog shows the current step while signing in, syncing, decrypting, and preparing the vault view. Locking a connected vault keeps its tab open and clears the decrypted view. If **Enable database quick unlock (Touch ID / Windows Hello)** is enabled and Windows Hello is available, the vault opens before the Windows Hello setup prompt. Then use **Unlock with Windows Hello** on the locked tab. You can also unlock with your master password. Quick Unlock keeps the password encrypted in memory. Disabling Quick Unlock, closing the tab, or exiting BitwardenXC clears the encrypted copy.

The bundled CLI opens a previously synchronized vault from the existing encrypted Bitwarden profile, even when the server is unavailable. BitwardenXC refreshes in the background after opening the vault and when you choose **Database → Sync Bitwarden**. The status icon at the bottom right shows progress and indicates when a refresh needs attention. Click the warning icon to retry after saving any open edits. Saving changes requires a connection to the server.

The bundled CLI applies edits to the existing login and keeps untouched data such as passkeys, the page-load autofill preference, and additional URLs. BitwardenXC checks the entry revision before saving. A separately installed upstream CLI can create personal logins and edit existing titles and notes. Organization logins and secure notes are read-only. Entries requiring a master-password reprompt are unavailable in the connected view. The connected tab uses the CLI's local account profile and encrypted cache. The CLI can persist authentication tokens and the API client secret in that local profile. The application opens the vault in memory. The original KDBX format remains available for local KeePass databases.

The Bitwarden connection runs a GPL build of the [official CLI](https://github.com/bitwarden/clients/tree/cli-v2026.10.1/apps/cli) with the [BitwardenXC patch](utils/bitwardenxc-cli-v2026.10.1.patch). Each Windows release includes `BitwardenXC-CLI-Source.zip`. See the [CLI documentation](https://bitwarden.com/help/cli/) for supported login methods and the [KeePassXC Windows build instructions](https://github.com/keepassxreboot/keepassxc/wiki/Set-up-Build-Environment-on-Windows) for the C++ and Qt dependencies. The BitwardenXC source is distributed under the terms in [COPYING](COPYING).

## KeePassXC upstream

[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/6326/badge)](https://bestpractices.coreinfrastructure.org/projects/6326)
[![TeamCity Build Status](https://ci.keepassxc.org/app/rest/builds/buildType:\(project:KeepassXC\)/statusIcon)](https://ci.keepassxc.org/?guest=1)
[![codecov](https://codecov.io/gh/keepassxreboot/keepassxc/branch/develop/graph/badge.svg)](https://codecov.io/gh/keepassxreboot/keepassxc)
[![GitHub release](https://img.shields.io/github/release/keepassxreboot/keepassxc)](https://github.com/keepassxreboot/keepassxc/releases/)

[![Matrix community channel](https://img.shields.io/matrix/keepassxc:matrix.org?label=Community%20channel)](https://app.element.io/#/room/#keepassxc:mozilla.org)
[![Matrix development channel](https://img.shields.io/matrix/keepassxc-dev:matrix.org?label=Development%20channel)](https://app.element.io/#/room/#keepassxc-dev:mozilla.org)

[KeePassXC](https://keepassxc.org) is a modern, secure, and open-source password manager that stores and manages your most sensitive information. You can run KeePassXC on Windows, macOS, and Linux systems. KeePassXC is for people with extremely high demands of secure personal data management. It saves many different types of information, such as usernames, passwords, URLs, attachments, and notes in an offline, encrypted file that can be stored in any location, including private and public cloud solutions. For easy identification and management, user-defined titles and icons can be specified for entries. In addition, entries are sorted into customizable groups. An integrated search function allows you to use advanced patterns to easily find any entry in your database. A customizable, fast, and easy-to-use password generator utility allows you to create passwords with any combination of characters or easy to remember passphrases.

## Quick Start

The [QuickStart Guide](https://keepassxc.org/docs/KeePassXC_GettingStarted.html) gets you started using KeePassXC on your Windows, macOS, or Linux computer using pre-compiled binaries from the [downloads page](https://keepassxc.org/download). Additionally, individual Linux distributions may ship their own versions, so please check your distribution's package list to see if KeePassXC is available. Detailed documentation is available in the [User Guide](https://keepassxc.org/docs/KeePassXC_UserGuide.html).

## Features List

KeePassXC has numerous features for novice and power users alike. Our goal is to create an application that can be used by anyone while still offering advanced features to those that need them.

### Core Features

* Create, open, and save databases in the KDBX format (KeePass-compatible with KDBX4 and KDBX3)
* All information is encrypted at rest and never exposed outside the program
* Store sensitive information in entries that are organized by groups
* Password generator
* Search for entries
* TOTP storage and generation
* YubiKey/OnlyKey challenge-response support
* Auto-Type passwords into applications
* Browser integration with Google Chrome, Mozilla Firefox, Microsoft Edge, Chromium, Vivaldi, Brave, and Tor-Browser
* Support for passkeys using the browser integration
* Entry icon download
* Import databases from CSV, 1Password, Bitwarden, Proton Pass, and KeePass1 formats

### Advanced
* Database reports (password health, HIBP, and statistics)
* Database export to CSV, XML, and HTML formats
* TOTP storage and generation
* Field references between entries
* File attachments and custom attributes
* Entry history and data restoration
* Command line interface (keepassxc-cli)
* SSH Agent integration
* FreeDesktop.org Secret Service (replace Gnome keyring, etc.)
* Additional encryption choices: Twofish and ChaCha20

For a full list of changes, read the [CHANGELOG](CHANGELOG.md) document. \
For a full list of keyboard shortcuts, see [KeyboardShortcuts.adoc](./docs/topics/KeyboardShortcuts.adoc)

## Building KeePassXC

Detailed instructions are available in the [Build and Install](./INSTALL.md) page and in the [Wiki](https://github.com/keepassxreboot/keepassxc/wiki/Building-KeePassXC).

## Contributing

We are always looking for suggestions on how to improve KeePassXC. If you find any bugs or have an idea for a new feature, please let us know by opening a report in the [issue tracker](https://github.com/keepassxreboot/keepassxc/issues) on GitHub, or join us on [Matrix community channel](https://matrix.to/#/!zUxwGnFkUyycpxeHeM:matrix.org?via=matrix.org) or [Matrix development channel](https://matrix.to/#/!RhJPJPGwQIFVQeXqZa:matrix.org?via=matrix.org), or on IRC in [Libera.Chat](https://web.libera.chat/) channels #keepassxc and #keepassxc-dev.

You may directly contribute your own code by submitting a pull request. Please read the [CONTRIBUTING](.github/CONTRIBUTING.md) document for further information.

Contributors are required to adhere to the project's [Code of Conduct](CODE-OF-CONDUCT.md).

## Generative AI

Generative AI is fast becoming a first-party feature in most development environments, including GitHub itself. If the majority of a code submission is made using Generative AI (e.g., agent-based or vibe coding) then **we will document that in the pull request.** All code submissions go through a rigorous review process regardless of the development workflow or submitter.

## License

KeePassXC code is licensed under GPL-2 or GPL-3. Additional licensing for third-party files is detailed in [COPYING](./COPYING).
