"""Private local-development mailbox; never a production email transport."""

import os
from pathlib import Path
from uuid import uuid4


class LocalMailbox:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def __call__(self, email: str, url: str) -> None:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.directory / f"{uuid4()}.txt"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(f"To: {email}\nRemy sign-in link (expires in 15 minutes):\n{url}\n")
