from collections.abc import Sequence
from typing import Any, TypedDict

import requests
from requests.models import HTTPBasicAuth


class KeaResponse(TypedDict):
    result: int
    arguments: dict[str, Any] | None
    text: str | None


class KeaClient:
    def __init__(
        self,
        url: str,
        username: str | None = None,
        password: str | None = None,
        verify: bool | str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        timeout: int = 30,
    ):
        if (client_cert is not None and client_key is None) or (
            client_cert is None and client_key is not None
        ):
            raise ValueError("Key and Cert must be used together.")

        self.url = url
        self.timeout = timeout

        self._session = requests.Session()
        if verify is not None:
            self._session.verify = verify
        if username is not None and password is not None:
            self._session.auth = HTTPBasicAuth(username, password)
        if client_cert is not None and client_key is not None:
            self._session.cert = (client_cert, client_key)

    def command(
        self,
        command: str,
        service: list[str] | None = None,
        arguments: dict[str, Any] | None = None,
        check: None | Sequence[int] = (0,),
    ) -> list[KeaResponse]:
        body: dict[str, Any] = {"command": command}

        if service is not None:
            body["service"] = service

        if arguments is not None:
            body["arguments"] = arguments

        resp = self._session.post(self.url, json=body, timeout=self.timeout)
        resp.raise_for_status()
        resp_json = resp.json()
        assert isinstance(resp_json, list)
        if check is not None:
            check_response(resp_json, check)
        return resp_json


class KeaException(Exception):
    def __init__(
        self, resp: KeaResponse, msg: str | None = None, index: int | None = None
    ) -> None:
        self.index = index
        self.response = resp

        if msg is None:
            msg = f"Kea returned result[{index}] {self.response.get('result')}"
        message = f"{msg}: {self.response.get('text')}"
        super().__init__(message)


def check_response(resp: list[KeaResponse], ok_codes: Sequence[int]) -> None:
    """Raise a KeaException for any non 0 responses."""
    for idx, kr in enumerate(resp):
        if kr["result"] not in ok_codes:
            raise KeaException(kr, index=idx)
