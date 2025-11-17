import os

from aws_cdk import App, Stack, Tags
import aws_cdk as cdk

from deployment.policies import SSMPermissionsConstruct
from deployment.s3_bucket import TruststoreBucketConstruct
from deployment.truststore import TruststoreConstruct
from deployment.networking import NetworkConstruct
from deployment.lambda_function import FastAPILambdaConstruct
from deployment.loadbalancer import LoadBalancer
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
        "certificate": "50752488-303e-4757-85d3-fea66ae0a2d0",
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

Tags.of(stack).add("ib1:p-perseus:owner", "kip.parker@ib1.org")
Tags.of(stack).add("ib1:p-perseus:stage", deployment_context)

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

# Create ELB Trust Store from the S3 bucket
truststore = TruststoreConstruct(
    stack,
    "Truststore",
    environment_name=contexts[deployment_context]["environment_name"],
    existing_bucket_name=truststore_bucket.bucket.bucket_name,
    truststore_key=truststore_bucket.truststore_key,
)

# Create networking (VPC for ALB)
network = NetworkConstruct(
    stack,
    "Network",
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

# Create Application Load Balancer with mTLS
alb = LoadBalancer(
    stack,
    "LoadBalancer",
    vpc=network.vpc,
    context=dict(contexts[deployment_context]),
    trust_store=truststore.trust_store,
    lambda_function=fastapi_lambda.function,
)

# Note: API Gateway deployment is commented out - using ALB instead
# api_gateway = DualApiGatewayConstruct(
#     stack,
#     "DualApiGateway",
#     context=dict(contexts[deployment_context]),
#     fastapi_lambda=fastapi_lambda.function,
#     authorizer=authorizer,
#     truststore_bucket=truststore_bucket,
# )
app.synth()
