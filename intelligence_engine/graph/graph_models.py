"""
SentinelX Knowledge Graph Models

Every asset type and relationship type is defined here.
No Neo4j code. No business logic. Pure data contracts.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid


class NodeType(str, Enum):
    ORGANIZATION  = "Organization"
    DOMAIN        = "Domain"
    SUBDOMAIN     = "Subdomain"
    IP            = "IP"
    ASN           = "ASN"
    PORT          = "Port"
    SERVICE       = "Service"
    CERTIFICATE   = "Certificate"
    TECHNOLOGY    = "Technology"
    EMAIL_SYSTEM  = "EmailSystem"
    DNS_RECORD    = "DnsRecord"
    CLOUD         = "Cloud"
    CDN           = "CDN"
    WAF           = "WAF"
    FINDING       = "Finding"
    ATTACK_PATH   = "AttackPath"


class RelType(str, Enum):
    OWNS                = "OWNS"
    HAS_SUBDOMAIN       = "HAS_SUBDOMAIN"
    RESOLVES_TO         = "RESOLVES_TO"
    HOSTS               = "HOSTS"
    USES                = "USES"
    EXPOSES             = "EXPOSES"
    HAS_PORT            = "HAS_PORT"
    HAS_FINDING         = "HAS_FINDING"
    HAS_CERTIFICATE     = "HAS_CERTIFICATE"
    CONNECTED_TO        = "CONNECTED_TO"
    SHARES_IP           = "SHARES_IP"
    SHARES_CERTIFICATE  = "SHARES_CERTIFICATE"
    SHARES_TECHNOLOGY   = "SHARES_TECHNOLOGY"
    TRUSTS              = "TRUSTS"
    DEPENDS_ON          = "DEPENDS_ON"
    LEADS_TO            = "LEADS_TO"
    PROTECTED_BY        = "PROTECTED_BY"
    REGISTERED_WITH     = "REGISTERED_WITH"
    PART_OF             = "PART_OF"


@dataclass
class Node:
    node_type:  NodeType
    name:       str
    properties: Dict[str, Any] = field(default_factory=dict)
    node_id:    str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "node_id":    self.node_id,
            "node_type":  self.node_type.value,
            "name":       self.name,
            "properties": self.properties,
        }


@dataclass
class Edge:
    source_id:  str
    target_id:  str
    rel_type:   RelType
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source_id":  self.source_id,
            "target_id":  self.target_id,
            "rel_type":   self.rel_type.value,
            "properties": self.properties,
        }
