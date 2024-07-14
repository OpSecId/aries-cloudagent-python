"""JSON-LD document loader methods."""

import asyncio
import concurrent.futures

from typing import Callable

from pydid.did_url import DIDUrl
from pyld.documentloader import requests as pyld_requests
from pyld.documentloader import aiohttp as pyld_aiohttp
from pyld import jsonld
from pyld.jsonld import JsonLdError, parse_link_header, LINK_HEADER_REL

from ..cache.base import BaseCache
from ..core.profile import Profile
from ..resolver.did_resolver import DIDResolver

from typing import Dict, Optional
import urllib.parse as urllib_parse
from importlib import resources
from ..version import __version__


import nest_asyncio
import logging
import re
import string
import requests

logger = logging.getLogger(__name__)

nest_asyncio.apply()


class DocumentLoaderException(Exception):
    """Base exception for document loader module."""


class DocumentLoader:
    """JSON-LD document loader."""

    def __init__(self, profile: Profile, cache_ttl: int = 300) -> None:
        """Initialize new DocumentLoader instance.

        Args:
            profile (Profile): The profile
            cache_ttl (int, optional): TTL for cached documents. Defaults to 300.

        """
        self.profile = profile
        self.resolver = profile.inject(DIDResolver)
        self.cache = profile.inject_or(BaseCache)
        self.online_request_loader = pyld_requests.requests_document_loader()
        self.requests_loader = StaticCacheJsonLdDownloader().load
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.cache_ttl = cache_ttl
        self._event_loop = asyncio.get_event_loop()

    async def _load_did_document(self, did: str, options: dict):
        # Resolver expects plain did without path, query, etc...
        # DIDUrl throws error if it contains no path, query etc...
        # This makes sure we get a plain did
        did = DIDUrl.parse(did).did if DIDUrl.is_valid(did) else did

        did_document = await self.resolver.resolve(self.profile, did)

        document = {
            "contentType": "application/ld+json",
            "contextUrl": None,
            "documentUrl": did,
            "document": did_document,
        }

        return document

    def _load_http_document(self, url: str, options: dict):
        document = self.requests_loader(url, options)

        return document

    # Async document loader can use await for cache and did resolver
    async def _load_async(self, url: str, options: dict):
        """Retrieve http(s) or did document."""

        # Resolve DIDs using did resolver
        if url.startswith("did:"):
            document = await self._load_did_document(url, options)
        elif url.startswith("http://") or url.startswith("https://"):
            document = self._load_http_document(url, options)
        else:
            raise DocumentLoaderException(
                "Unrecognized url format. Must start with "
                "'did:', 'http://' or 'https://'"
            )

        return document

    async def load_document(self, url: str, options: dict):
        """Load JSON-LD document.

        Method signature conforms to PyLD document loader interface

        Document loading is processed in separate thread to deal with
        async to sync transformation.
        """
        cache_key = f"json_ld_document_resolver::{url}"

        # Try to get from cache
        if self.cache:
            document = await self.cache.get(cache_key)
            if document:
                return document

        document = await self._load_async(url, options)

        # Cache document, if cache is available
        if self.cache:
            await self.cache.set(cache_key, document, self.cache_ttl)

        return document

    def __call__(self, url: str, options: dict):
        """Load JSON-LD Document."""

        loop = self._event_loop
        coroutine = self.load_document(url, options)
        document = loop.run_until_complete(coroutine)

        return document


def _load_jsonld_file(
    original_url, filename: str, resource_path: str = f"{__package__}.resources"
):
    """Load context from package.

    Given a URL and filename,
    load a context in the format used by pyld document loader.
    """
    return {
        "contentType": "application/ld+json",
        "contextUrl": None,
        "documentUrl": original_url,
        "document": (resources.files(resource_path) / filename).read_text(),
    }


class StaticCacheJsonLdDownloader:
    """Context downloader with filesystem static cache for common contexts."""

    CONTEXT_FILE_MAPPING = {
        "https://www.w3.org/2018/credentials/v1": "context/credentials_v1.jsonld",
        "https://www.w3.org/ns/credentials/v2": "context/credentials_v2.jsonld",
        "https://www.w3.org/ns/did/v1": "context/did_documents_v1.jsonld",
        "https://w3id.org/security/v2": "context/security_v2.jsonld",
        "https://w3id.org/security/jwk/v1": "context/security_jwk_v1.jsonld",
        "https://w3id.org/security/multikey/v1": "context/security_multikey_v1.jsonld",
        "https://w3id.org/security/data-integrity/v2": "context/security_data_integrity_v2.jsonld",
        "https://w3id.org/security/suites/ed25519-2020/v1": "context/security_suites_ed25519_2020_v1.jsonld",
    }

    def __init__(
        self,
        document_downloader: Optional["JsonLdDocumentDownloader"] = None,
        document_parser: Optional["JsonLdDocumentParser"] = None,
    ):
        """Load static document on initialization."""
        self.documents_downloader = document_downloader or JsonLdDocumentDownloader()
        self.document_parser = document_parser or JsonLdDocumentParser()

        self.cache = {
            url: self.document_parser.parse(_load_jsonld_file(url, filename), None)
            for url, filename in StaticCacheJsonLdDownloader.CONTEXT_FILE_MAPPING.items()
        }

    def load(self, url: str, options: Optional[Dict] = None):
        """Load a jsonld document from URL.

        Prioritize local static cache before attempting to download from the URL.
        """
        cached = self.cache.get(url)

        if cached is not None:
            logger.info("Local cache hit for context: %s", url)
            return cached

        logger.debug("Context %s not in static cache, resolving from URL.", url)
        return self._live_load(url, options)

    def _live_load(self, url: str, options: Optional[Dict] = None):
        doc, link_header = self.documents_downloader.download(url, options)
        return self.document_parser.parse(doc, link_header)


class JsonLdDocumentDownloader:
    """JsonLd documents downloader."""

    def download(self, url: str, options: Optional[Dict], **kwargs):
        """Retrieves JSON-LD at the given URL.

        This was lifted from pyld.documentloader.requests.

        :param url: the URL to retrieve.
        :param options:

        :return: the RemoteDocument.

        """
        options = options or {}

        try:
            # validate URL
            pieces = urllib_parse.urlparse(url)
            if (
                not all([pieces.scheme, pieces.netloc])
                or pieces.scheme not in ["http", "https"]
                or set(pieces.netloc)
                > set(string.ascii_letters + string.digits + "-.:")
            ):
                raise JsonLdError(
                    'URL could not be dereferenced; only "http" and "https" '
                    "URLs are supported.",
                    "jsonld.InvalidUrl",
                    {"url": url},
                    code="loading document failed",
                )
            if options.get("secure") and pieces.scheme != "https":
                raise JsonLdError(
                    "URL could not be dereferenced; secure mode enabled and "
                    'the URL\'s scheme is not "https".',
                    "jsonld.InvalidUrl",
                    {"url": url},
                    code="loading document failed",
                )
            headers = options.get("headers")
            if headers is None:
                headers = {"Accept": "application/ld+json, application/json"}
            headers["User-Agent"] = f"AriesCloudAgent/{__version__}"
            response = requests.get(url, headers=headers, **kwargs)

            content_type = response.headers.get("content-type")
            if not content_type:
                content_type = "application/octet-stream"
            doc = {
                "contentType": content_type,
                "contextUrl": None,
                "documentUrl": response.url,
                "document": response.json(),
            }

            return doc, response.headers.get("link")
        except Exception as cause:
            raise JsonLdError(
                "Could not retrieve a JSON-LD document from the URL.",
                "jsonld.LoadDocumentError",
                code="loading document failed",
                cause=cause,
            )


class JsonLdDocumentParser:
    """JsonLd documents parser."""

    def parse(self, doc: Dict, link_header: Optional[str]):
        """Parse a jsonld document after retrieval.

        This was lifted from pyld.documentloader.requests.
        """
        try:
            if link_header:
                linked_context = parse_link_header(link_header).get(LINK_HEADER_REL)
                # only 1 related link header permitted
                if linked_context and doc["content_type"] != "application/ld+json":
                    if isinstance(linked_context, list):
                        raise JsonLdError(
                            "URL could not be dereferenced, "
                            "it has more than one "
                            "associated HTTP Link Header.",
                            "jsonld.LoadDocumentError",
                            {"url": doc["url"]},
                            code="multiple context link headers",
                        )
                    doc["contextUrl"] = linked_context["target"]
                linked_alternate = parse_link_header(link_header).get("alternate")
                # if not JSON-LD, alternate may point there
                if (
                    linked_alternate
                    and linked_alternate.get("type") == "application/ld+json"
                    and not re.match(
                        r"^application\/(\w*\+)?json$", doc["content_type"]
                    )
                ):
                    doc["contentType"] = "application/ld+json"
                    doc["documentUrl"] = jsonld.prepend_base(
                        doc["url"], linked_alternate["target"]
                    )
            return doc
        except JsonLdError as e:
            raise e
        except Exception as cause:
            raise JsonLdError(
                "Could not retrieve a JSON-LD document from the URL.",
                "jsonld.LoadDocumentError",
                code="loading document failed",
                cause=cause,
            )


DocumentLoaderMethod = Callable[[str, dict], dict]

__all__ = ["DocumentLoaderMethod", "DocumentLoader"]
