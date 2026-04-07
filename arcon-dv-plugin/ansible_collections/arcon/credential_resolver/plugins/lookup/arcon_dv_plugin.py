# -*- coding: utf-8 -*-
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Copyright (c) 2024, Arcon Tech Solutions <ansible@arcontech.in>
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
name: arcon_dv_plugin
short_description: Retrieve password from ARCON PAM
description:
  - Lookup plugin to fetch credentials from ARCON PAM.
version_added: "1.0.0"
author:
  - Arcon Tech Solutions (@arcon-tech)
options:
  _terms:
    description:
      - Input format C(/ip/service_type/username).
    required: true
    type: str
notes:
  - Requires network access to the ARCON PAM API endpoint.
  - All configuration is read from environment variables.
  - Set ARCON_HOST, ARCON_USERNAME, ARCON_PASSWORD before running.
'''

EXAMPLES = r'''
- name: Retrieve a credential from ARCON PAM DV
  ansible.builtin.debug:
    msg: "{{ lookup('arcon.credential_resolver.arcon_dv_plugin', '/192.168.1.10/1/admin') }}"
'''

RETURN = r'''
_raw:
  description: A list containing the retrieved password from ARCON PAM.
  type: list
  elements: str
'''

import os
import json
import time
import warnings

try:
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    HAS_REQUESTS = True
    HAS_REQUESTS_ERR = None
except ImportError as imp_exc:
    HAS_REQUESTS = False
    HAS_REQUESTS_ERR = imp_exc
    requests = None
    urllib3 = None
    InsecureRequestWarning = None

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

warnings.filterwarnings("ignore")
display = Display()

if urllib3:
    urllib3.disable_warnings(InsecureRequestWarning)
    urllib3.disable_warnings()

# ---------------- GLOBAL CACHE ----------------

TOKEN_CACHE = {
    "token": None,
    "expiry": 0
}

SESSION = requests.Session() if requests else None


class ArconClient:

    def __init__(self, host, username, password, retry_count, retry_delay):
        self.host = host
        self.username = username
        self.password = password
        self.retry_count = retry_count
        self.retry_delay = retry_delay

    # ---------------- RETRY ----------------

    def request_with_retry(self, method, url, **kwargs):

        for attempt in range(self.retry_count):
            try:
                response = SESSION.request(method, url, timeout=15, **kwargs)
                response.raise_for_status()
                return response
            except Exception as e:
                if attempt == self.retry_count - 1:
                    raise AnsibleError("API call failed: {0}".format(str(e)))

                sleep_time = self.retry_delay * (2 ** attempt)
                display.v("Retrying in {0}s".format(sleep_time))
                time.sleep(sleep_time)

    # ---------------- TOKEN ----------------

    def get_token(self):

        if TOKEN_CACHE["token"] and time.time() < TOKEN_CACHE["expiry"]:
            display.v("Using cached token")
            return TOKEN_CACHE["token"]

        url = "{0}/arconapigateway/dv/api/sdk/GetToken".format(self.host)

        payload = json.dumps({
            "Username": self.username,
            "Password": self.password
        })

        headers = {
            "Content-Type": "application/json"
        }

        response = self.request_with_retry(
            "POST",
            url,
            headers=headers,
            data=payload,
            verify=False
        )

        data = response.json()

        try:
            token = data["Result"]["accessToken"]
            expiry = data["Result"]["expiresIn"]  # noqa: F841
        except Exception:
            raise AnsibleError("Invalid token response")

        # cache token (10 mins fallback)
        TOKEN_CACHE["token"] = token
        TOKEN_CACHE["expiry"] = time.time() + 600

        return token

    # ---------------- PASSWORD ----------------

    def get_password(self, ip, username):

        token = self.get_token()

        url = "{0}/arconapigateway/dv/api/sdk/GetTargetDevicePassKey".format(self.host)

        payload = json.dumps([
            {
                "ServerIp": ip,
                "TargetType": "Linux",
                "UserName": username,
                "DbInstanceName": "",
                "OpenForHours": "1"
            }
        ])

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(token)
        }

        response = self.request_with_retry(
            "POST",
            url,
            headers=headers,
            data=payload,
            verify=False
        )

        data = response.json()

        try:
            password = data["Result"][0]["Password"]
        except Exception:
            raise AnsibleError("Password not found in response")

        return password


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        if not HAS_REQUESTS:
            raise AnsibleError(
                "The 'requests' Python library is required. "
                "Install it with: pip install requests. "
                "Error: {0}".format(HAS_REQUESTS_ERR)
            )

        if not terms:
            raise AnsibleError("Input must be /ip/service_type/username")

        terms = " ".join(terms)
        parts = terms.split("/")

        try:
            ip = parts[1]
            username = parts[3]
        except Exception:
            raise AnsibleError("Invalid format: /ip/service_type/username")

        host = os.environ.get("ARCON_HOST")
        user = os.environ.get("ARCON_USERNAME")
        password = os.environ.get("ARCON_PASSWORD")
        retry_count = int(os.environ.get("ARCON_RETRY_COUNT", 3))
        retry_delay = int(os.environ.get("ARCON_RETRY_DELAY", 2))

        if not host:
            raise AnsibleError("ARCON_HOST environment variable is not set")
        if not user:
            raise AnsibleError("ARCON_USERNAME environment variable is not set")
        if not password:
            raise AnsibleError("ARCON_PASSWORD environment variable is not set")

        client = ArconClient(host, user, password, retry_count, retry_delay)

        pwd = client.get_password(ip, username)

        return [pwd]
