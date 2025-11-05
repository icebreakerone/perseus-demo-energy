import os


from aws_cdk import App, Stack, Tags  # type: ignore
import aws_cdk as cdk


from deployment.networking import NetworkConstruct
from deployment.policies import SSMPermissionsConstruct
from deployment.truststore import TruststoreConstruct
from deployment.elasticache import RedisConstruct

from deployment.authentication_service import AuthenticationAPIServiceConstruct
from deployment.dynamodb import DynamoDBConstruct
from deployment.loadbalancer import LoadBalancer
from models import Context

app = App()

deployment_context = app.node.try_get_context("deployment_context") or "dev"

HOSTED_ZONE_NAME = "perseus-demo-authentication.ib1.org"
contexts: dict[str, Context] = {
    "dev": {
        "environment_name": "dev",
        "mtls_subdomain": "preprod.mtls",
        "mtls_certificate": "507e3751-89c9-4e71-888f-9d22eed4f085",
        "subdomain": "preprod",
        "certificate": "54953fe2-52bf-4568-8242-4ab0115bac18",
        "hosted_zone_name": HOSTED_ZONE_NAME,
    },
    "prod": {
        "environment_name": "prod",
        "mtls_subdomain": "mtls",
        "mtls_certificate": "9a286285-c171-447e-9ce1-06ddcd343ca5",
        "subdomain": "",
        "certificate": "d4547c2b-3c08-4f5d-b709-663e27ea0ebf",
        "hosted_zone_name": HOSTED_ZONE_NAME,
    },
}

stack = Stack(
    app,
    f"AuthenticationStack-{deployment_context}",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION")
    ),
)

# Add tags to the stack
Tags.of(stack).add("ib1:p-perseus:owner", "kip.parker@ib1.org")
Tags.of(stack).add("ib1:p-perseus:stage", deployment_context)

network = NetworkConstruct(
    stack, "Network", environment_name=contexts[deployment_context]["environment_name"]
)
ssm_policy = SSMPermissionsConstruct(
    stack,
    "SSMPermissions",
    app_name="perseus-demo-authentication",
    env_name=contexts[deployment_context]["environment_name"],
)
redis = RedisConstruct(
    stack,
    "Redis",
    vpc=network.vpc,
    redis_sg=network.redis_sg,
    env_name=contexts[deployment_context]["environment_name"],
)

# Create truststore using the existing S3 bucket from the resource deployment
truststore = TruststoreConstruct(
    stack,
    "Truststore",
    environment_name=contexts[deployment_context]["environment_name"],
    existing_bucket_name=f"perseus-resource-truststore-{contexts[deployment_context]['environment_name']}",
    truststore_key="bundle.pem",
)

alb = LoadBalancer(
    stack,
    "ALB",
    vpc=network.vpc,
    context=contexts[deployment_context],
    trust_store=truststore.trust_store,
)

dynamodb = DynamoDBConstruct(
    stack,
    "DynamoDB",
    vpc=network.vpc,
    env_name=contexts[deployment_context]["environment_name"],
)
fastapi_service = AuthenticationAPIServiceConstruct(
    stack,
    "FastAPIService",
    vpc=network.vpc,
    ssm_policy=ssm_policy.policy,
    environment={
        "API_DOMAIN": f'{contexts[deployment_context]["mtls_subdomain"]}.{contexts[deployment_context]["hosted_zone_name"]}',
        "UNPROTECTED_URL": f'https://{contexts[deployment_context]["subdomain"]}.{contexts[deployment_context]["hosted_zone_name"]}',
        "JWT_SIGNING_KEY": f"/copilot/perseus-demo-authentication/{deployment_context}/secrets/jwt-signing-key",
        "REDIS_HOST": redis.redis.attr_redis_endpoint_address,
        "ORY_CLIENT_ID": "f67916ce-de33-4e2f-a8e3-cbd5f6459c30",
        "ORY_URL": "https://vigorous-heyrovsky-1trvv0ikx9.projects.oryapis.com",
        "ISSUER_URL": f"https://{contexts[deployment_context]["mtls_subdomain"]}.{contexts[deployment_context]["hosted_zone_name"]}",
        "ORY_CLIENT_SECRET_PARAM": f"/copilot/perseus-demo-authentication/{deployment_context}/secrets/client_secret",
        "DYNAMODB_TABLE": dynamodb.table.table_name,
        "PROVIDER_ROLE": "https://registry.core.sandbox.trust.ib1.org/scheme/perseus/role/carbon-accounting-provider",
    },
    ecs_sg=network.ecs_sg,
    mtls_target_group=alb.mtls_target_group,
    public_target_group=alb.public_target_group,
    mtls_alb_sg=alb.mtls_alb_sg,
    public_alb_sg=alb.public_alb_sg,
    table=dynamodb.table,
)

app.synth()
