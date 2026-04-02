#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests
import urllib3
import time
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()
urllib3.disable_warnings()

DOCUMENTATION = r'''
lookup: arcon
author:
  - Arcon Tech Solutions
version_added: "1.0.0"

short_description: Retrieve password from ARCON PAM

description:
  - Lookup plugin to fetch credentials from ARCON PAM.

options:
  arcon_host:
    description: ARCON PAM host URL
    required: True
    env:
      - name: ARCON_HOST

  arcon_username:
    description: ARCON API username
    required: True
    env:
      - name: ARCON_USERNAME

  arcon_password:
    description: ARCON API password
    required: True
    env:
      - name: ARCON_PASSWORD

  retry_count:
    description: API retry attempts
    default: 3

  retry_delay:
    description: Delay between retries
    default: 2

  _terms:
    description:
      - Input format /ip/service_type/username
    required: True
'''

# ---------------- GLOBAL CACHE ----------------

TOKEN_CACHE = {
    "token": None,
    "expiry": 0
}

SESSION = requests.Session()


class ArconClient:

    def __init__(self, host, username, password, retry_count, retry_delay):

        self.host = host
        self.username = username
        self.password = password
        self.retry_count = retry_count
        self.retry_delay = retry_delay

    # ---------------- RETRY HELPER ----------------

    def request_with_retry(self, method, url, **kwargs):

        for attempt in range(self.retry_count):

            try:

                response = SESSION.request(method, url, timeout=10, **kwargs)

                response.raise_for_status()

                return response

            except Exception as e:

                if attempt == self.retry_count - 1:
                    raise AnsibleError(f"API call failed: {str(e)}")

                sleep_time = self.retry_delay * (2 ** attempt)
                display.warning(f"Retrying API call in {sleep_time}s")

                time.sleep(sleep_time)

    # ---------------- TOKEN GENERATION ----------------

    def get_token(self):

        global TOKEN_CACHE

        if TOKEN_CACHE["token"] and time.time() < TOKEN_CACHE["expiry"]:
            display.v("Using cached ARCON token")
            return TOKEN_CACHE["token"]

        url = f"{self.host}/arconToken"

        # payload = {
        #     "username": self.username,
        #     "password": self.password,
        #     "grant_type": "password"
        # }

        payload = f"grant_type=password&username={self.username}&password={self.password}"
        print(payload)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = self.request_with_retry(
            "POST",
            url,
            headers=headers,
            data=payload,
            verify=False
        )

        token_data = response.json()
        token = token_data.get("access_token")

        if not token:
            raise AnsibleError("Token missing from ARCON response")

        # cache token for 10 minutes
        TOKEN_CACHE["token"] = token
        TOKEN_CACHE["expiry"] = time.time() + 600

        return token

    # ---------------- PASSWORD FETCH ----------------

    def get_password(self, ip, username, service_type):

        token = self.get_token()

        url = f"{self.host}/api/ServicePassword/GetTargetDevicePassKey"

        payload = [
            {
                "ServerIp": ip,
                "ServiceTypeID": service_type,
                "UserName": username,
                "DbInstanceName": "",
                "OpenForHours": "1"
            }
        ]

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = self.request_with_retry(
            "POST",
            url,
            headers=headers,
            json=payload,
            verify=False
        )

        result = response.json()

        try:
            password = result["Result"][0]["Password"]
        except Exception:
            raise AnsibleError("Password not found in ARCON response")

        return password


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        if not terms:
            raise AnsibleError("Input format must be /ip/service_type/username")

        terms = " ".join(terms)
        parts = terms.split("/")

        try:
            ip = parts[1]
            service_type = parts[2]
            username = parts[3]
        except Exception:
            raise AnsibleError("Invalid input format. Use /ip/service_type/username")

        host = self.get_option("arcon_host")
        user = self.get_option("arcon_username")
        password = self.get_option("arcon_password")

        retry_count = int(self.get_option("retry_count"))
        retry_delay = int(self.get_option("retry_delay"))

        client = ArconClient(
            host,
            user,
            password,
            retry_count,
            retry_delay
        )

        pwd = client.get_password(ip, username, service_type)

        return [pwd]