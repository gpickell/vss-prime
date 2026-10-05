## Goal

The ultimate goal is to provide a tool that is simple to run on a
windows machine without admin privileges. The user will start by
doing `winget install uv` then `uv tool install <url>`.

The tool will do a number of things but it'll target a `/opt/vertigis-studio/`
on a remote Linux machine and manage a number of materials there: certs, keys,
account identification.

## Approach for Work

We'll keep extending this document to capture how the tool should work. Each
section marked `step` will indicate a substantial focus and the next activity
for the tool. I will indicate a step is done implementation using a COMPLETE.

Claude may modify this document when a detail is missing and settled, but keep
edits minimal. I want to drive mostly.

NOTES:
- Local Settings: ~/.vss-prime
- Scratch Location: ~/.vss-prime/scratch
- lib: sshconf
- lib: questionary

## Step: Use gsudo to sudo (COMPLETE)

Perform elevation on start: --sudo

## Step: Install OpenSSH (COMPLETE)

Test if ssh is available. if not, install it.

Force Install: --force-ssh-install

## Step: Ensure ed25519 Key (COMPLETE)

Ensure the user has a id_ed25519(.pub) key pair.

## Step: Create/Choose a SSH profile (COMPLETE)

Flow:
- Pick from a list if any (host1, host2, ..., new)
  - remembered
- If new:
  - Ask for Profile Name
  - Ask for Host
  - Ask for User

## Step: Remote Execute Facility (COMPLETE)

## Step: Propagate Keys for Auto-Logon (COMPLETE)

## Step: Provisioning (COMPLETE)

Flow provision.sh:
- checks for docker and installs it
- adds user to docker group
- provisions /opt/vertigis-studio
- group: docker
- permissions: g+ws + default rwx

Flow:
- copy provision.sh
- ssh sh provision.sh  

Force Install: --force-provision

## Step: Grab Account ID (COMPLETE)

Flow:
- Open up temp server on localhost
- Invite the user to click a SIMPLE link
- Once the Account ID is known, stash it in /opt/vertigis-studio/account.txt

## Step: Manual Certificate Enrollment (COMPLETE)

The goal here is to provide a enrollment wizard of sorts.

Structure of /opt/vertigis-studio/certs/live:
- < cn / hostname >
  - live/cert.pem
  - live/chain.pem
  - live/fullchain.pem
  - live/privkey.pem

Structure of /opt/vertigis-studio/certs/enroll:
- < cn >
  - sans.txt
  - cert.csr
  - privkey.pem

How enrollment is done:
- if we need more tools, we should ensure this is done in provisioning.
- initialize the cert.csr and privkey.pem
- use host's admin context to "act as machine" 
  - use windows actual CLI tools
    - you probably need -AdminForceMachine
- once collected propagate back to live folder

Flow:
- Loop 1: add cn/sans
  - List all the combos of cn: san (one per line)
  - Ask: Add another cert/san?
    - Ask: Certificate: name
      - remembered
    - Ask: SAN (FQDN): 
- Loop 2: enroll cert (skipped if none available)
  - Pick: Certificate: name
    - OR: Not Now (default)
  - Pick: Enroll Now? Pick CA (error if none seen)
    - Actually issues the enrollment request
      - stashes it in the user's .vss-prime
- Loop 3: check for enrollment (skipped if none available or no enrollments pending)
  - Pick Certificate: name
    - OR: Not Now (default)
    - OR: Clear (cleanup pending)
- Loop 4: update the live certs from staging (skipped if none available or no enrollment results)
  - Pick Certificate: name
    - OR: Not Now (default)
    - OR: Clear (cleanup staging)

## Step: Scrape CA Material (COMPLETE)

Flow:
- Ask: Transfer this system's CA trust anchors.
- Update /opt/vertigis-studio/certs/trust
  - Shape it like /etc/ssl/certs (because that is how we'll mount it)
    - mind the sym links, we'll have to make these local to folder
    - triage the filenames
