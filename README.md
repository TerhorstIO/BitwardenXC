# BitwardenXC

BitwardenXC is a Windows fork of KeePassXC 2.8.0. Bitwarden and Vaultwarden vaults open in the KeePassXC folder tree, entry table and detail view. The native clipboard shortcuts, including `Ctrl+B` for username and `Ctrl+C` for password, and the KeePassXC Auto-Type engine work on entries in the connected vault.

1. Download the standalone Windows CLI from the [Bitwarden CLI releases](https://github.com/bitwarden/clients/releases?q=cli-v&expanded=true) and extract `bw.exe`.
2. Start BitwardenXC and choose **Database → Open Bitwarden / Vaultwarden**. Select `bw.exe`, then enter your server's HTTPS address, email and master password. For Bitwarden Cloud use `https://vault.bitwarden.com` or `https://vault.bitwarden.eu`.
3. For two-step login, enter an authenticator code if required. The personal API key option signs in via the [Bitwarden CLI API-key flow](https://bitwarden.com/help/personal-api-key/) and still needs your master password to unlock the vault.
4. Edit the title or notes of an existing personal login and use `Ctrl+S` to write them to the server. Use **Database → Sync Bitwarden** to pull changes made on another device. Locking the connected vault closes its tab. Reopen it through the database menu.

The connected vault supports reading logins and secure notes and saving the title and notes of existing personal logins. The CLI can reset a login's page-load autofill setting when it rewrites the login fields. BitwardenXC leaves those fields out of edit requests and checks the entry revision before saving. Entries requiring a master-password reprompt are unavailable in the connected view. The connected tab uses the CLI's local account profile and encrypted cache. The CLI can persist authentication tokens and the API client secret in that local profile. The application opens the vault in memory. The original KDBX format remains available for local KeePass databases.

The Bitwarden connection uses the official CLI as a subprocess. See the [CLI documentation](https://bitwarden.com/help/cli/) for supported login methods and the [KeePassXC Windows build instructions](https://github.com/keepassxreboot/keepassxc/wiki/Set-up-Build-Environment-on-Windows) for the C++ and Qt dependencies. The source is distributed under the terms in [COPYING](COPYING).

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
