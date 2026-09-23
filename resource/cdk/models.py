from typing import TypedDict


class Context(TypedDict):
    environment_name: str
    mtls_subdomain: str
    trust_store: str
    subdomain: str
    hosted_zone_name: str
    hosted_zone_id: str
    scheme_base_url: str
