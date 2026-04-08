# ARCON Credential Resolver

## Overview
Ansible lookup plugin to fetch credentials from ARCON PAM.

## Installation
ansible-galaxy collection install arcon-credential_resolver_dv-<version>.tar.gz

## Configuration
- export ARCON_HOST=https://<ARCON_SERVER>:<SERVER_PORT>
- export ARCON_USERNAME=<ENCODED_USERNAME>
- export ARCON_PASSWORD=<ENCODED_PASSWORD>

## Usage
lookup('arcon.credential_resolver_dv.arcon_dv_plugin', '/135.235.136.171/7/user1')

## Notes
- No hardcoded passwords
- Token-based authentication