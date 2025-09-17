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
    Stack,
    CfnOutput,
)
from constructs import Construct
from .authorizer import CertificateAuthorizerConstruct


class DualApiGatewayConstruct(Construct):
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

        # ========== mTLS API Gateway ==========
        # Reference existing CloudWatch log group for mTLS API Gateway access logs
        mtls_log_group_name = (
            f"/aws/apigateway/perseus-resource-mtls-{context['environment_name']}"
        )
        self.mtls_access_log_group = logs.LogGroup.from_log_group_name(
            self,
            "MTLSApiGatewayAccessLogs",
            log_group_name=mtls_log_group_name,
        )

        # Create HTTP API Gateway v2 with mTLS for secure endpoints
        self.mtls_api = apigwv2.HttpApi(
            self,
            "MTLSResourceAPI",
            api_name=f"perseus-resource-mtls-{context['environment_name']}",
            description="Perseus Energy Demo Resource API (mTLS)",
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
                max_age=Duration.days(1),
            ),
            default_integration=apigwv2_integrations.HttpLambdaIntegration(
                "DefaultIntegration", fastapi_lambda
            ),
        )

        # Create custom domain for mTLS API
        self.mtls_domain = apigwv2.DomainName(
            self,
            "MTLSDomain",
            domain_name=f"{context['mtls_subdomain']}.{context['hosted_zone_name']}",
            certificate=acm.Certificate.from_certificate_arn(
                self,
                "MTLSCertificate",
                f"arn:aws:acm:{Stack.of(self).region}:{Stack.of(self).account}:certificate/{context['mtls_certificate']}",
            ),
            mtls=apigwv2.MTLSConfig(
                bucket=truststore_bucket.bucket,  # type: ignore
                key=getattr(truststore_bucket, "truststore_key", "bundle.pem"),
                # Remove version to avoid issues with newly uploaded files
            ),
        )

        # Add dependency on bucket deployment if it exists
        if hasattr(truststore_bucket, "bucket_deployment"):
            self.mtls_domain.node.add_dependency(truststore_bucket.bucket_deployment)

        # Create API mapping for mTLS domain
        apigwv2.ApiMapping(
            self,
            "MTLSApiMapping",
            domain_name=self.mtls_domain,
            api=self.mtls_api,
        )

        # Create Lambda authorizer for mTLS API
        self.mtls_lambda_authorizer = apigwv2_auth.HttpLambdaAuthorizer(
            "MTLSCertificateAuthorizer",
            handler=authorizer.authorizer_function,
            identity_source=[
                "$request.header.Host"
            ],  # Use Host header as identity source
            results_cache_ttl=Duration.seconds(0),  # Disable caching for mTLS
        )

        # Create Lambda integration for mTLS API
        self.mtls_lambda_integration = apigwv2_integrations.HttpLambdaIntegration(
            "MTLSLambdaIntegration",
            fastapi_lambda,
        )

        # Add routes to mTLS API (secure endpoints)
        self.mtls_api.add_routes(
            path="/datasources",
            methods=[apigwv2.HttpMethod.GET],
            integration=self.mtls_lambda_integration,
            authorizer=self.mtls_lambda_authorizer,
        )

        self.mtls_api.add_routes(
            path="/datasources/{id}/{measure}",
            methods=[apigwv2.HttpMethod.GET],
            integration=self.mtls_lambda_integration,
            authorizer=self.mtls_lambda_authorizer,
        )

        # ========== Public API Gateway ==========
        # Reference existing CloudWatch log group for public API Gateway access logs
        public_log_group_name = (
            f"/aws/apigateway/perseus-resource-public-{context['environment_name']}"
        )
        self.public_access_log_group = logs.LogGroup.from_log_group_name(
            self,
            "PublicApiGatewayAccessLogs",
            log_group_name=public_log_group_name,
        )

        # Create HTTP API Gateway v2 without mTLS for public endpoints
        self.public_api = apigwv2.HttpApi(
            self,
            "PublicResourceAPI",
            api_name=f"perseus-resource-public-{context['environment_name']}",
            description="Perseus Energy Demo Resource API (Public)",
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
                max_age=Duration.days(1),
            ),
            default_integration=apigwv2_integrations.HttpLambdaIntegration(
                "PublicDefaultIntegration", fastapi_lambda
            ),
        )

        # Create custom domain for public API
        self.public_domain = apigwv2.DomainName(
            self,
            "PublicDomain",
            domain_name=f"{context['subdomain']}.{context['hosted_zone_name']}",
            certificate=acm.Certificate.from_certificate_arn(
                self,
                "PublicCertificate",
                f"arn:aws:acm:{Stack.of(self).region}:{Stack.of(self).account}:certificate/{context['certificate']}",
            ),
            # No mTLS config for public domain
        )

        # Create API mapping for public domain
        apigwv2.ApiMapping(
            self,
            "PublicApiMapping",
            domain_name=self.public_domain,
            api=self.public_api,
        )

        # Create Lambda integration for public API
        self.public_lambda_integration = apigwv2_integrations.HttpLambdaIntegration(
            "PublicLambdaIntegration",
            fastapi_lambda,
        )

        # Add routes to public API (documentation and public endpoints)
        self.public_api.add_routes(
            path="/",
            methods=[apigwv2.HttpMethod.GET],
            integration=self.public_lambda_integration,
            # No authorizer for public endpoints
        )

        self.public_api.add_routes(
            path="/docs",
            methods=[apigwv2.HttpMethod.GET],
            integration=self.public_lambda_integration,
            # No authorizer for documentation
        )

        self.public_api.add_routes(
            path="/openapi.json",
            methods=[apigwv2.HttpMethod.GET],
            integration=self.public_lambda_integration,
            # No authorizer for OpenAPI spec
        )

        self.public_api.add_routes(
            path="/redoc",
            methods=[apigwv2.HttpMethod.GET],
            integration=self.public_lambda_integration,
            # No authorizer for ReDoc
        )

        # Create Route53 records for both domains
        hosted_zone = route53.HostedZone.from_lookup(
            self,
            "HostedZone",
            domain_name=context["hosted_zone_name"],
            private_zone=False,
        )

        # mTLS domain A record
        route53.ARecord(
            self,
            "MTLSAliasRecord",
            zone=hosted_zone,
            record_name=(context["mtls_subdomain"] if context["subdomain"] else None),
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayv2DomainProperties(
                    regional_domain_name=self.mtls_domain.regional_domain_name,
                    regional_hosted_zone_id=self.mtls_domain.regional_hosted_zone_id,
                )
            ),
        )

        # Public domain A record
        route53.ARecord(
            self,
            "PublicAliasRecord",
            zone=hosted_zone,
            record_name=context["subdomain"] if context["subdomain"] else None,
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayv2DomainProperties(
                    regional_domain_name=self.public_domain.regional_domain_name,
                    regional_hosted_zone_id=self.public_domain.regional_hosted_zone_id,
                )
            ),
        )

        # Outputs
        CfnOutput(
            self,
            "MTLSApiGatewayUrl",
            value=self.mtls_api.url or "",
            description="mTLS API Gateway URL",
        )

        CfnOutput(
            self,
            "MTLSCustomDomainUrl",
            value=f"https://{self.mtls_domain.name}",
            description="mTLS Custom Domain URL",
        )

        CfnOutput(
            self,
            "PublicApiGatewayUrl",
            value=self.public_api.url or "",
            description="Public API Gateway URL",
        )

        CfnOutput(
            self,
            "PublicCustomDomainUrl",
            value=f"https://{self.public_domain.name or ''}",
            description="Public Custom Domain URL",
        )

        CfnOutput(
            self,
            "MTLSApiGatewayAccessLogGroup",
            value=self.mtls_access_log_group.log_group_name,
            description="mTLS API Gateway Access Log Group",
        )

        CfnOutput(
            self,
            "PublicApiGatewayAccessLogGroup",
            value=self.public_access_log_group.log_group_name,
            description="Public API Gateway Access Log Group",
        )
