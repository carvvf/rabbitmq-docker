"""Read GHCR tags through the authenticated Distribution API, including bootstrap."""

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from .build_inputs import github_authentication

NAME = "carvvf/rabbitmq-docker"
TAGS_PATH = f"/v2/{NAME}/tags/list"


def registry_json(url, authorization):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "ghcr.io":
        raise ValueError("Registry credentials may only be sent to https://ghcr.io")
    request = urllib.request.Request(url, headers={"Authorization": authorization, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response), response.headers.get("Link", "")


def registry_token():
    credential, _ = github_authentication()
    if not credential:
        raise ValueError("Authenticated GHCR access is required to enumerate publication tags")
    user = os.environ.get("GITHUB_ACTOR", "carvvf")
    basic = base64.b64encode(f"{user}:{credential}".encode()).decode()
    query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{NAME}:pull"})
    value, _ = registry_json("https://ghcr.io/token?" + query, "Basic " + basic)
    token = value.get("token") or value.get("access_token")
    if not isinstance(token, str) or not token:
        raise ValueError("GHCR did not return a registry access token")
    return token


def package_tags():
    """Only authenticated NAME_UNKNOWN on the first page means a new package."""
    authorization = "Bearer " + registry_token()
    url = "https://ghcr.io" + TAGS_PATH + "?n=100"
    seen = set()
    tags = []
    while url:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "ghcr.io" or parsed.path != TAGS_PATH:
            raise ValueError("Unexpected GHCR tag pagination URL")
        if url in seen:
            raise ValueError("GHCR tag pagination repeated a page")
        seen.add(url)
        try:
            page, links = registry_json(url, authorization)
        except urllib.error.HTTPError as error:
            if error.code == 404 and len(seen) == 1:
                details = json.load(error)
                codes = {entry.get("code") for entry in details.get("errors", [])}
                if codes == {"NAME_UNKNOWN"}:
                    return []
            raise
        values = page.get("tags")
        if page.get("name") != NAME or "tags" not in page or (values is not None and (
            not isinstance(values, list) or not all(isinstance(tag, str) for tag in values)
        )):
            raise ValueError("Invalid GHCR tag listing")
        tags.extend(values or [])
        match = re.search(r'<([^>]+)>;\s*rel="next"', links)
        url = urllib.parse.urljoin(url, match[1]) if match else ""
    return tags
