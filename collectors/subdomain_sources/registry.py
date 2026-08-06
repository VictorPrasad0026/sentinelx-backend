"""
SentinelX Discovery Registry

Central registry for all discovery sources.

Adding a new discovery source only requires:
1. Importing the discover function
2. Registering it below
"""

from collectors.subdomain_sources.crtsh import get_ct_subdomains
from collectors.subdomain_sources.certspotter import get_certspotter
from collectors.subdomain_sources.alienvault_otx import get_otx_subdomains
from collectors.subdomain_sources.recursive import recursive_discovery
from collectors.subdomain_sources.dns_zone_transfer import check_zone_transfer


DISCOVERY_SOURCES = {
    "crtsh": get_ct_subdomains,
    "certspotter": get_certspotter,
    "otx": get_otx_subdomains,
    "recursive": recursive_discovery,
    "zone_transfer": check_zone_transfer,
}