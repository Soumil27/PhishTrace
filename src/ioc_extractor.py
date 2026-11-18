
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit
import re


URL_PATTERN = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)


def extract_iocs(file_path):
    path = Path(file_path)

    with path.open("rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except (LookupError, UnicodeError):
                    continue
    else:
        try:
            body_parts.append(message.get_content())
        except (LookupError, UnicodeError):
            pass

    body = "\n".join(str(part) for part in body_parts)
    urls = sorted({
        match.rstrip(".,;:!?)\\]}")
        for match in URL_PATTERN.findall(body)
    })

    domains = sorted({
        urlsplit(url).hostname.lower()
        for url in urls
        if urlsplit(url).hostname
    })

    return {
        "source_file": path.name,
        "urls": urls,
        "domains": domains,
        "url_count": len(urls),
        "domain_count": len(domains),
        "note": "Extracted indicators are not automatically malicious."
    }
