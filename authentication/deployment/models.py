from typing import TypedDict


class Context(TypedDict):
    environment_name: str
    mtls_subdomain: str
    mtls_certificate: str
    trust_store: str
    subdomain: str
    certificate: str
    hosted_zone_name: str
    hosted_zone_id: str
