#!/usr/bin/python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests
import urllib3
import time
import json
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.filterwarnings("ignore")

urllib3.disable_warnings(InsecureRequestWarning)
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

    # ---------------- RETRY ----------------

    def request_with_retry(self, method, url, **kwargs):

        for attempt in range(self.retry_count):
            try:
                response = SESSION.request(method, url, timeout=15, **kwargs)
                response.raise_for_status()
                return response
            except Exception as e:
                if attempt == self.retry_count - 1:
                    raise AnsibleError(f"API call failed: {str(e)}")

                sleep_time = self.retry_delay * (2 ** attempt)
                display.v(f"Retrying in {sleep_time}s")
                time.sleep(sleep_time)

    # ---------------- TOKEN ----------------

    def get_token(self):

        global TOKEN_CACHE

        if TOKEN_CACHE["token"] and time.time() < TOKEN_CACHE["expiry"]:
            display.v("Using cached token")
            return TOKEN_CACHE["token"]

        url = f"{self.host}/arconapigateway/dv/api/sdk/GetToken"

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
            expiry = data["Result"]["expiresIn"]
        except Exception:
            raise AnsibleError("Invalid token response")

        # cache token (10 mins fallback)
        TOKEN_CACHE["token"] = token
        TOKEN_CACHE["expiry"] = time.time() + 600

        return token

    # ---------------- PASSWORD ----------------

    def get_password(self, ip, username):

        token = self.get_token()

        url = f"{self.host}/arconapigateway/dv/api/sdk/GetTargetDevicePassKey"

        payload = json.dumps([
            {
                "ServerIp": ip,
                "TargetType": "Linux",   # change if needed
                "UserName": username,
                "DbInstanceName": "",
                "OpenForHours": "1"
            }
        ])

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
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
        if not terms:
            raise AnsibleError("Input must be /ip/service_type/username")

        terms = " ".join(terms)
        parts = terms.split("/")

        try:
            ip = parts[1]
            username = parts[3]
        except:
            raise AnsibleError("Invalid format: /ip/service_type/username")

        host = self.get_option("arcon_host")
        user = self.get_option("arcon_username")
        password = self.get_option("arcon_password")

        retry_count = int(self.get_option("retry_count"))
        retry_delay = int(self.get_option("retry_delay"))

        client = ArconClient(host, user, password, retry_count, retry_delay)

        pwd = client.get_password(ip, username)

        return [pwd]