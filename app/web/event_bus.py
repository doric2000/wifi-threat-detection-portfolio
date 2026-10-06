"""
event_bus.py — In-process async pub/sub for analyzer → WebSocket fan-out.
"""

import asyncio
import logging
from typing import Set

logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue):
        async with self._lock:
            self._subscribers.discard(q)

    def publish(self, event: dict):
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Subscriber queue full — dropping event")


bus = EventBus()
