import os
from aws_cdk import (
    aws_apigatewayv2 as apigwv2,
    aws_apigatewayv2_integrations as apigwv2_integrations,
    aws_apigatewayv2_authorizers as apigwv2_auth,
    aws_certificatemanager as acm,
    aws_route53 as route53,
    aws_route53_targets as targets,
    aws_s3 as s3,
    aws_lambda as lambda_,
    aws_logs as logs,
    Duration,
    CfnOutput,
)
from constructs import Construct
from .authorizer import CertificateAuthorizerConstruct


class ApiGatewayConstruct(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        context: dict,
        fastapi_lambda: lambda_.Function,
        authorizer: CertificateAuthorizerConstruct,
        truststore_bucket: s3.Bucket,
    ):
        super().__init__(scope, id)

        # Reference existing CloudWatch log group for API Gateway access logs
        # This will use the existing log group if it exists, or create a new one if it doesn't
        log_group_name = (
            f"/aws/apigateway/perseus-resource-{context['environment_name']}"
        )
        self.access_log_group = logs.LogGroup.from_log_group_name(
            self,
            "ApiGatewayAccessLogs",
            log_group_name=log_group_name,
        )

        # Create HTTP API Gateway v2 with access logging
        self.api = apigwv2.HttpApi(
            self,
            "ResourceAPI",
            api_name=f"perseus-resource-{context['environment_name']}",
            description="Perseus Energy Demo Resource API",
            cors_preflight=apigwv2.CorsPreflightOptions(
                allow_origins=["*"],
                allow_methods=[
                    apigwv2.CorsHttpMethod.GET,
                    apigwv2.CorsHttpMethod.POST,
                    apigwv2.CorsHttpMethod.PUT,
                    apigwv2.CorsHttpMethod.DELETE,
                    apigwv2.CorsHttpMethod.OPTIONS,
                ],
                allow_headers=["*"],
            ),
        )

        # Configure access logging for the default stage
        # Get the default stage and configure access logging
        default_stage = self.api.default_stage
        if default_stage:
            cfn_stage = default_stage.node.default_child
            if cfn_stage:
                # Set access log settings directly using setattr to avoid type issues
                setattr(
                    cfn_stage,
                    "access_log_settings",
                    apigwv2.CfnStage.AccessLogSettingsProperty(
                        destination_arn=self.access_log_group.log_group_arn,
                        format='{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","caller":"$context.identity.caller","user":"$context.identity.user","requestTime":"$context.requestTime","httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath","status":"$context.status","protocol":"$context.protocol","responseLength":"$context.responseLength"}',
                    ),
                )

        # Create custom domain
        domain_name = (
            f"{context['subdomain']}.{context['hosted_zone_name']}"
            if context["subdomain"]
            else context["hosted_zone_name"]
        )

        # Get certificate
        certificate = acm.Certificate.from_certificate_arn(
            self,
            "Certificate",
            f"arn:aws:acm:eu-west-2:232615051732:certificate/{context['certificate']}",
        )

        # Create custom domain with mTLS
        self.domain = apigwv2.DomainName(
            self,
            "CustomDomain",
            domain_name=domain_name,
            certificate=certificate,
            mtls=apigwv2.MTLSConfig(
                bucket=truststore_bucket.bucket,  # type: ignore
                key=getattr(truststore_bucket, "truststore_key", "bundle.pem"),
                # Remove version to avoid issues with newly uploaded files
            ),
        )

        # Add dependency on bucket deployment if it exists
        if (
            hasattr(truststore_bucket, "bucket_deployment")
            and truststore_bucket.bucket_deployment
        ):
            self.domain.node.add_dependency(truststore_bucket.bucket_deployment)

        # Create API mapping
        apigwv2.ApiMapping(
            self,
            "ApiMapping",
            domain_name=self.domain,
            api=self.api,
        )

        # Create Lambda authorizer using the authorizers module
        self.lambda_authorizer = apigwv2_auth.HttpLambdaAuthorizer(
            "CertificateAuthorizer",
            handler=authorizer.authorizer_function,
            identity_source=[
                "$request.header.Host"
            ],  # Use Host header as identity source
            results_cache_ttl=Duration.seconds(0),  # Disable caching for mTLS
        )

        # Create Lambda integration
        self.lambda_integration = apigwv2_integrations.HttpLambdaIntegration(
            "LambdaIntegration",
            fastapi_lambda,
        )

        # Add proxy route to handle all paths
        self.api.add_routes(
            path="/{proxy+}",
            methods=[apigwv2.HttpMethod.ANY],
            integration=self.lambda_integration,
            authorizer=self.lambda_authorizer,
        )

        # Add root route
        self.api.add_routes(
            path="/",
            methods=[apigwv2.HttpMethod.ANY],
            integration=self.lambda_integration,
            authorizer=self.lambda_authorizer,
        )

        # Create Route53 record
        hosted_zone = route53.HostedZone.from_lookup(
            self,
            "HostedZone",
            domain_name=context["hosted_zone_name"],
            private_zone=False,
        )

        route53.ARecord(
            self,
            "AliasRecord",
            zone=hosted_zone,
            record_name=context["subdomain"] if context["subdomain"] else None,
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayv2DomainProperties(
                    regional_domain_name=self.domain.regional_domain_name,
                    regional_hosted_zone_id=self.domain.regional_hosted_zone_id,
                )
            ),
        )

        # Outputs
        CfnOutput(
            self,
            "ApiGatewayUrl",
            value=self.api.url or "https://api.example.com",
            description="API Gateway URL",
        )

        CfnOutput(
            self,
            "CustomDomainUrl",
            value=f"https://{domain_name}",
            description="Custom Domain URL",
        )

        CfnOutput(
            self,
            "AccessLogGroup",
            value=self.access_log_group.log_group_name,
            description="API Gateway Access Log Group",
        )
