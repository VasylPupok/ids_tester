from dataclasses import dataclass


@dataclass(unsafe_hash=True)
class Technique:
    uid: int
    name: str


@dataclass(unsafe_hash=True)
class Alert:
    uid: int
    rule_id: str


@dataclass(unsafe_hash=True)
class Payload:
    uid: int
    payload: str
