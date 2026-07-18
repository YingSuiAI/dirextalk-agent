#!/usr/bin/python3.12
"""Fixed production entrypoint for python3.12 -I -S -B."""

import os
import sys

# Under -I/-S no current directory or site package path is trusted. These are
# the only two non-stdlib roots added by the sealed release.
sys.path.extend(
    [
        "/opt/dirextalk/knowledge/current/adapter",
        "/opt/dirextalk/knowledge/current/pydeps",
    ]
)

from dirextalk_knowledge.auth import PeerAuthorizer  # noqa: E402
from dirextalk_knowledge.embedding import production_embedder  # noqa: E402
from dirextalk_knowledge.ledger import Ledger  # noqa: E402
from dirextalk_knowledge.qdrant import QdrantClient  # noqa: E402
from dirextalk_knowledge.server import Server  # noqa: E402
from dirextalk_knowledge.service import KnowledgeService  # noqa: E402
from dirextalk_knowledge.staging import StagingStore  # noqa: E402


def main() -> None:
    os.umask(0o077)
    ledger = Ledger()
    staging = StagingStore()
    service = KnowledgeService(production_embedder(), QdrantClient(), ledger, staging)
    service.initialize()
    Server(service, PeerAuthorizer()).serve_forever()


if __name__ == "__main__":
    main()
