from typing import TypedDict


class Context(TypedDict):
    environment_name: str
    mtls_subdomain: str
    subdomain: str
    hosted_zone_name: str
    scheme_base_url: str
