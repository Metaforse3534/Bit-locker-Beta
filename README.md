# Bit-locker-Beta
Short description

This script provides a safe, explicit GUI for disabling BitLocker on local Windows machines.

This is not a “click once and oops your disk is naked” tool. It forces the user to slow down and make deliberate choices.

Important

Run this only on machines you own and administer.

Always back up recovery keys before disabling BitLocker.

Nothing happens automatically. You must explicitly:

select volumes

create backups

acknowledge the risks

click Start

If you manage to break your system anyway, that part is on you.

Features

Detects all BitLocker-enabled volumes

Creates local backups of recovery protectors

default: bitlocker_backups/

or a user-selected folder

Requires explicit risk acknowledgement via checkbox

Start and Cancel buttons only, no hidden automation

Progress and log output shown in the GUI

Writes logs to Bit.log in the application directory

Usage

Open PowerShell as Administrator.

Navigate to the folder and run:

python Bit.py


Select drives, click Backup selected, choose a folder or use the default.

Check the agreement box and click Start.

Security notes

Recovery key backups and logs are stored locally only.

Do not share recovery keys with third parties unless you enjoy consequences.

Packaging, distribution and monetization (MenthaForce Coperation)

Yes, this is structured for actual distribution, not a zip file thrown over a fence.

Overview

Packaging files included:

pyproject.toml

build_installer.ps1

Inno Setup template: innosetup_template.iss

Product branding:

Company: MenthaForce Coperation

Version: 0.1.0

Recommended steps for selling

Code signing (strongly recommended)
Buy an EV Code Signing certificate and sign both the installer and executable to avoid SmartScreen warnings.

Build executable

pip install pyinstaller


Run:

.\build_installer.ps1


This produces dist\MenthaForceBitLocker.exe.

Create installer
Install Inno Setup and run innosetup_template.iss, or let the build script call ISCC automatically.

License enforcement

Current implementation uses a local demo/license file for testing.

Replace LOCAL_LICENSE_SECRET in Bit.py before distribution.

For production, use server-side license validation or a commercial licensing service.

Legal documents

Update EULA.txt and LICENSE with proper legal text.

Payments & fulfillment

Suggested providers: FastSpring, Paddle, Gumroad, or Stripe combined with license delivery.

Testing

Generate a 7-day demo license via:

GUI: Demo license

CLI:

python Bit.py --demo-license

Dev Mode

Set or generate a Dev Mode code via:

GUI: Set/Generate Code

CLI:

python Bit.py --set-dev-code mycode [--hide] [--persist-state]


Options:

--hide: store the code encrypted so it cannot be revealed later

--persist-state: Dev Mode survives restarts

Dev Mode temporarily bypasses license checks for testing.

Storage uses Windows DPAPI when available, with an encrypted fallback.

Do not leave Dev Mode enabled in production unless you like self-sabotage.

UI & usability

Clear header and status bar

EULA and Terms accessible via:

Help → View EULA

Help → View Terms

README.md, EULA.txt, and TERMS.txt can be viewed inside the app and opened in Notepad

Installation and UAC behavior should be tested in a Windows VM

Website & releases

Simple website included in site/:

index, download, install, terms

GitHub Actions workflows:

release.yml: builds Windows artifacts on tag vX.Y.Z

deploy_site.yml: deploys site to GitHub Pages

Replace placeholder GitHub URLs before publishing, unless you enjoy broken links.

Security and release hardening

Do not include .py source files in release artifacts

Build script copies only:

compiled executable

legal documents

Uses PyInstaller --onefile

Consider:

PyInstaller --key for bytecode encryption

PyArmor or similar obfuscation tools

Always code-sign both executable and installer before public release
