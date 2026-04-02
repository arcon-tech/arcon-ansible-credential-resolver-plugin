# ARCON Credential Resolver

## Overview
Ansible lookup plugin to fetch credentials from ARCON PAM.

## Installation
ansible-galaxy collection install arcon-credential_resolver-<version>.tar.gz

## Configuration
export ARCON_HOST=https://<ARCON_SERVER>:<PORT>
export ARCON_USERNAME=<ENCODED_USERNAME>
export ARCON_PASSWORD=<ENCODED_PASSWORD>

## Usage
lookup('arcon.credential_resolver.arcon_plugin', '/135.235.136.171/7/user1')

## Notes
- No hardcoded passwords
- Token-based authentication