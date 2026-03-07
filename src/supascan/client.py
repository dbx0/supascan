from __future__ import annotations
from typing import Any, Optional

import requests

from .models import Credentials


class SupabaseClient:
    def __init__(self, creds: Credentials, verbose: bool = False):
        self.creds = creds
        self.verbose = verbose
        self._session = requests.Session()
        self._session.headers.update({
            "apikey": creds.anon_key,
            "Authorization": f"Bearer {creds.anon_key}",
            "Content-Type": "application/json",
        })

    def use_anon_key(self) -> None:
        self._session.headers["Authorization"] = f"Bearer {self.creds.anon_key}"

    def use_user_token(self) -> None:
        if self.creds.user_token:
            self._session.headers["Authorization"] = f"Bearer {self.creds.user_token}"

    def _url(self, path: str) -> str:
        return f"{self.creds.base_url}{path}"

    def _log(self, method: str, url: str, status: int) -> None:
        if self.verbose:
            print(f"  [{method}] {url} → {status}")

    def get_openapi_spec(self) -> requests.Response:
        url = self._url("/rest/v1/")
        resp = self._session.get(url)
        self._log("GET", url, resp.status_code)
        return resp

    def get_auth_settings(self) -> requests.Response:
        url = self._url("/auth/v1/settings")
        resp = self._session.get(url)
        self._log("GET", url, resp.status_code)
        return resp

    def query_table(
        self,
        table: str,
        limit: int = 5,
        csv: bool = False,
        anon: bool = False,
    ) -> requests.Response:
        if anon:
            self.use_anon_key()
        headers = {}
        if csv:
            headers["Accept"] = "text/csv"
        url = self._url(f"/rest/v1/{table}?limit={limit}")
        resp = self._session.get(url, headers=headers)
        self._log("GET", url, resp.status_code)
        return resp

    def insert_row(self, table: str, row: dict) -> requests.Response:
        url = self._url(f"/rest/v1/{table}")
        resp = self._session.post(
            url,
            json=row,
            headers={"Prefer": "return=representation"},
        )
        self._log("POST", url, resp.status_code)
        return resp

    def update_row(
        self,
        table: str,
        filter_col: str,
        filter_val: Any,
        patch: dict,
    ) -> requests.Response:
        url = self._url(f"/rest/v1/{table}?{filter_col}=eq.{filter_val}")
        resp = self._session.patch(url, json=patch)
        self._log("PATCH", url, resp.status_code)
        return resp

    def delete_row(
        self,
        table: str,
        filter_col: str,
        filter_val: Any,
    ) -> requests.Response:
        url = self._url(f"/rest/v1/{table}?{filter_col}=eq.{filter_val}")
        resp = self._session.delete(url)
        self._log("DELETE", url, resp.status_code)
        return resp

    def signup(self, email: str, password: str) -> requests.Response:
        url = self._url("/auth/v1/signup")
        resp = self._session.post(url, json={"email": email, "password": password})
        self._log("POST", url, resp.status_code)
        return resp

    def signin(self, email: str, password: str) -> requests.Response:
        url = self._url("/auth/v1/token?grant_type=password")
        resp = self._session.post(url, json={"email": email, "password": password})
        self._log("POST", url, resp.status_code)
        return resp

    def list_buckets(self) -> requests.Response:
        url = self._url("/storage/v1/bucket")
        resp = self._session.get(url)
        self._log("GET", url, resp.status_code)
        return resp

    def list_bucket_objects(self, bucket: str) -> requests.Response:
        url = self._url(f"/storage/v1/object/list/{bucket}")
        resp = self._session.post(url, json={"prefix": "", "limit": 100})
        self._log("POST", url, resp.status_code)
        return resp

    def call_edge_function(
        self,
        name: str,
        payload: Optional[dict] = None,
        include_auth: bool = True,
    ) -> requests.Response:
        url = f"https://{self.creds.project_ref}.functions.supabase.co/{name}"
        headers = {}
        if not include_auth:
            headers["Authorization"] = ""
        resp = self._session.post(url, json=payload or {}, headers=headers)
        self._log("POST", url, resp.status_code)
        return resp

    def call_rpc(self, name: str, payload: Optional[dict] = None) -> requests.Response:
        url = self._url(f"/rest/v1/rpc/{name}")
        resp = self._session.post(url, json=payload or {})
        self._log("POST", url, resp.status_code)
        return resp
