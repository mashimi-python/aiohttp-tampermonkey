import re
import logging
import asyncio
from io import BytesIO
from tampermonkey import GM

from aiohttp.client import ClientSession
from aiohttp.helpers import sentinel
from aiohttp.client_reqrep import ClientResponse, RequestInfo
from aiohttp import payload
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL


logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


orig_client_session_request = ClientSession._request


class TampermonkeyStreamReader(BytesIO):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._exception = None

    def read(self, *args, **kwargs):
        logger.debug("args: %r", args)
        logger.debug("kwargs: %r", kwargs)
        return super().read(*args, **kwargs)

    def set_exception(self, exception):
        self._exception = exception

    def exception(self):
        return self._exception


class TampermonkeyClientResponse(ClientResponse):
    """Compatible with https://github.com/aio-libs/aiohttp/blob/master/aiohttp/client_reqrep.py#L761
    """

    @classmethod
    def from_tampermonkey(cls, method, url, headers, response):
        url = URL(url)
        url_without_fragment = url.with_fragment(None) if url.raw_fragment else url
        request_info = RequestInfo(url=url_without_fragment, method=method, headers=headers, real_url=url)
        client_response = cls(method, URL(response['finalUrl']), writer=None, continue100=None, timer=None,
                              request_info=request_info, traces=[], loop=asyncio.get_running_loop(), session=None)
        client_response.tampermonkey_response = response
        client_response.status = response['status']
        client_response.reason = response['statusText']
        # set up headers
        logger.debug("response['responseHeaders']: %r", response['responseHeaders'])
        client_response._raw_headers = client_response._parse_headers_txt(response['responseHeaders'])
        headers_str = [(k.decode('ascii'), v.decode('ascii')) for k, v in client_response.raw_headers]
        response_headers = CIMultiDict(headers_str)
        client_response._headers = CIMultiDictProxy(response_headers)
        # set up content
        if isinstance(response['response'], str):
            response_bytes = response['response'].encode('utf-8')
        else:
            response_bytes = bytes(response['response'])
        client_response.content = TampermonkeyStreamReader(response_bytes)
        return client_response

    def _parse_headers_txt(self, _response_headers):
        matches = re.findall(r"^([^:]+):\s*(.+)\r$", _response_headers, flags=re.MULTILINE)
        logger.debug("matches: %r", matches)
        headers_bytes = ((k.encode('ascii'), v.encode('ascii')) for k, v in matches)
        return headers_bytes

    async def read(self, *args, **kwargs):
        logger.debug("args: %r", args)
        logger.debug("kwargs: %r", kwargs)
        logger.debug("self._body: %r", self._body)
        self._body = self.content.read(*args, **kwargs)
        logger.debug("self._body: %r", self._body)
        return self._body


async def client_session_request(self,
    method,
    str_or_url,
    *,
    params=None,
    data=None,
    json=None,
    cookies=None,
    headers=None,
    skip_auto_headers=None,
    auth=None,
    allow_redirects=True,
    max_redirects=10,
    compress=False,
    chunked=None,
    expect100=False,
    raise_for_status=None,
    read_until_eof=True,
    proxy=None,
    proxy_auth=None,
    timeout=sentinel,
    ssl=True,
    server_hostname=None,
    proxy_headers=None,
    trace_request_ctx=None,
    read_bufsize=None,
    auto_decompress=None,
    max_line_size=None,
    max_field_size=None,
):
    logger.debug("method: %r", method)
    logger.debug("url: %r", str_or_url)
    logger.debug("headers: %r", headers)
    logger.debug("data: %r", data)
    logger.debug("json: %r", json)

    if data is not None and json is not None:
        raise ValueError(
            "data and json parameters can not be used at the same time"
        )
    elif json is not None:
        data = payload.JsonPayload(json, dumps=self._json_serialize)._value

    # Merge with default headers and transform to CIMultiDict
    headers = self._prepare_headers(headers)

    # Convert to make it work correctly for GM.xmlHttpRequest
    if (content_type := headers.get('content-type', None)) and 'application/json' in content_type:
        if hasattr(data, 'decode'):
            data = data.decode('utf-8')
    headers = dict(headers) if headers else None
    tampermonkey_response = await GM.xmlHttpRequest(method=method, url=str(str_or_url), headers=headers, data=data, responseType='arraybuffer')
    logger.debug("tampermonkey_response: %r", tampermonkey_response)
    client_response = TampermonkeyClientResponse.from_tampermonkey(method, str_or_url, headers, tampermonkey_response)
    return client_response


def monkeypatch():
    ClientSession._request = client_session_request


def monkeypatch_disable():
    ClientSession._request = orig_client_session_request
