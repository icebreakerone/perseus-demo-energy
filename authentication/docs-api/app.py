#!/usr/bin/env python3
import os

import aws_cdk as cdk

from docs_api.docs_api_stack import DocsApiStack


app = cdk.App()
DocsApiStack(
    app,
    "DocsApiStack",
)

app.synth()
