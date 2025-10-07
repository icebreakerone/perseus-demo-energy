import os

from aws_cdk import App, Stack
import aws_cdk as cdk

from deployment.policies import SSMPermissionsConstruct
from deployment.authorizer import CertificateAuthorizerConstruct
from deployment.s3_bucket import TruststoreBucketConstruct
from deployment.lambda_function import FastAPILambdaConstruct
from deployment.dual_api_gateway import DualApiGatewayConstruct
from models import Context

app = App()

deployment_context = app.node.try_get_context("deployment_context") or "dev"
HOSTED_ZONE_NAME = "perseus-demo-energy.ib1.org"
contexts: dict[str, Context] = {
    "dev": {
        "environment_name": "dev",
        "mtls_subdomain": "preprod.mtls",
        "trust_store": "PerseusDemoTruststore/90ae6295e483d9f9",
        "subdomain": "preprod",
        "mtls_certificate": "fd59453d-a782-4728-a78c-ee8c37a3717e",
        "certificate": "535b09e0-4f69-41ad-853a-316754f81e6b",
        "hosted_zone_name": HOSTED_ZONE_NAME,
    },
    "prod": {
        "environment_name": "prod",
        "mtls_subdomain": "mtls",
        "trust_store": "PerseusDemoTruststore/90ae6295e483d9f9",
        "subdomain": "",
        "certificate": "d4547c2b-3c08-4f5d-b709-663e27ea0ebf",
        "mtls_certificate": "dc498c29-daa3-4eab-bd0e-dcce2d4de2c2",
        "hosted_zone_name": HOSTED_ZONE_NAME,
    },
}

cdk_env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION")
)

# Create main stack
stack = Stack(
    app,
    f"PerseusResourceApiStack-{deployment_context}",
    env=cdk_env,
    description=f"Resource API deployment for {deployment_context} environment",
)

# Create SSM permissions policy
ssm_policy = SSMPermissionsConstruct(
    stack,
    "SSMPermissions",
    app_name="perseus-demo-energy",
    env_name=contexts[deployment_context]["environment_name"],
)

# Create S3 bucket for truststore
truststore_file_path = os.path.join(
    os.path.dirname(__file__),
    "truststores",
    f"directory-{deployment_context}-client-certificates",
    "bundle.pem",
)
truststore_bucket = TruststoreBucketConstruct(
    stack,
    "TruststoreBucket",
    environment_name=contexts[deployment_context]["environment_name"],
    truststore_file_path=truststore_file_path,
)

# Create Lambda authorizer
authorizer = CertificateAuthorizerConstruct(
    stack,
    "CertificateAuthorizer",
    environment_name=contexts[deployment_context]["environment_name"],
)

# Create FastAPI Lambda function
fastapi_lambda = FastAPILambdaConstruct(
    stack,
    "FastAPILambda",
    environment_name=contexts[deployment_context]["environment_name"],
    ssm_policy=ssm_policy.policy,
    environment_variables={
        "LOG_LEVEL": "info",
        "ISSUER_URL": "https://perseus-demo-authentication.ib1.org",
        "API_DOMAIN": (
            f"{contexts[deployment_context]['subdomain']}.{contexts[deployment_context]['hosted_zone_name']}"
            if contexts[deployment_context]["subdomain"]
            else contexts[deployment_context]["hosted_zone_name"]
        ),
        "ENV": contexts[deployment_context]["environment_name"],
        "SIGNING_KEY": f"/copilot/perseus-demo-energy/{deployment_context}/secrets/signing-key",
        "SIGNING_ROOT_CA_CERTIFICATE": "s3://perseus-demo-energy-certificate-store/signing-root-ca.pem",
        "SIGNING_BUNDLE": "s3://perseus-demo-energy-certificate-store/signing-issued-bundle.pem",
        "AUTHENTICATION_SERVER": (
            f"https://{contexts[deployment_context]['subdomain']}.perseus-demo-authentication.ib1.org"
            if contexts[deployment_context]["subdomain"]
            else "https://perseus-demo-authentication.ib1.org"
        ),
    },
)

# Create API Gateway
print(f"Creating API Gateway for {deployment_context}")
print(f"Truststore bucket: {truststore_bucket.bucket.bucket_name}")
print(f"FastAPI Lambda: {fastapi_lambda.function.function_name}")
print(f"Authorizer: {authorizer.authorizer_function.function_name}")
print(f"Context: {contexts[deployment_context]}")

api_gateway = DualApiGatewayConstruct(
    stack,
    "DualApiGateway",
    context=dict(contexts[deployment_context]),
    fastapi_lambda=fastapi_lambda.function,
    authorizer=authorizer,
    truststore_bucket=truststore_bucket,
)

app.synth()
