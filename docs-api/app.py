#!/usr/bin/env python3
import os

import aws_cdk as cdk

from docs_api.docs_api_stack import DocsApiStack


app = cdk.App()


deployment_context = (
    app.node.try_get_context("deployment_context") or "authentication-dev"
)

contexts = {
    "authentication-dev": {
        "deployment_name": "EDPAuthenticationDocs",
        "environment_name": "dev",
        "domain_name": "docs.preprod.perseus-demo-authentication.ib1.org",
        "folder": "authentication",
    },
    "authentication-prod": {
        "deployment_name": "EDPAuthenticationDocs",
        "environment_name": "prod",
        "domain_name": "docs.perseus-demo-authentication.ib1.org",
        "folder": "authentication",
    },
    "resource-dev": {
        "deployment_name": "EDPResourceDocs",
        "environment_name": "dev",
        "domain_name": "docs.preprod.perseus-demo-energy.ib1.org",
        "folder": "resource",
    },
    "resource-prod": {
        "deployment_name": "EDPResourceDocs",
        "environment_name": "prod",
        "domain_name": "docs.perseus-demo-energy.ib1.org",
        "folder": "resource",
    },
}
DocsApiStack(
    app,
    f"{contexts[deployment_context]['deployment_name']}-{contexts[deployment_context]['environment_name']}",
    domain_name=contexts[deployment_context]["domain_name"],
    folder=contexts[deployment_context]["folder"],
    env=cdk.Environment(account=os.getenv("CDK_DEFAULT_ACCOUNT"), region="us-east-1"),
)

app.synth()
