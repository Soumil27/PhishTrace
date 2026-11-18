from email import policy
from email.parser import BytesParser
from pathlib import Path
from email.utils import getaddresses, parsedate_to_datetime
import json
import sys


def parse_email(file_path):
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Email file not found: {path}")

    with path.open("rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    def extract_addresses(header_name):
        return [
            {"name": name, "email": address}
            for name, address in getaddresses(message.get_all(header_name, []))
            if name or address
        ]

    try:
        email_date = parsedate_to_datetime(message["Date"]).isoformat()
    except (TypeError, ValueError, OverflowError):
        email_date = str(message.get("Date", ""))

    result = {
        "file": path.name,
        "from": extract_addresses("From"),
        "to": extract_addresses("To"),
        "cc": extract_addresses("Cc"),
        "reply_to": extract_addresses("Reply-To"),
        "return_path": str(message.get("Return-Path", "")),
        "subject": str(message.get("Subject", "")),
        "date": email_date,
        "message_id": str(message.get("Message-ID", "")),
        "received_headers": message.get_all("Received", []),
        "authentication_results": message.get_all(
            "Authentication-Results", []
        ),
        "all_headers": [
            {"name": name, "value": str(value)}
            for name, value in message.items()
        ],
    }

    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python src/email_parser.py <email.eml>")
        sys.exit(1)

    try:
        result = parse_email(sys.argv[1])
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)