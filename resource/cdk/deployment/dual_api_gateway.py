import json
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
    aws_iam as iam,
    Duration,
    Stack,
    CfnOutput,
    RemovalPolicy,
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
        truststore_bucket,  # TruststoreBucketConstruct instance
    ):
        super().__init__(scope, id)

        # ========== mTLS API Gateway ==========
        # Reference existing CloudWatch log group for mTLS API Gateway access logs
        mtls_access_log_group = logs.LogGroup(
            self,
            "MTLSApiGatewayAccessLogs",
            log_group_name=f"/aws/apigateway/perseus-resource-mtls-{context['environment_name']}",
            removal_policy=RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.ONE_WEEK,
        )
        mtls_access_log_group.add_to_resource_policy(
            iam.PolicyStatement(
                principals=[iam.ServicePrincipal("apigateway.amazonaws.com")],
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[
                    mtls_access_log_group.log_group_arn,
                    f"{mtls_access_log_group.log_group_arn}:*",
                ],
            )
        )

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
            # No default_integration - all routes must be explicitly defined with authorizer
        )

        # Access logs are configured later with the full format including client certificate fields
        # Create custom domain for mTLS API
        # Get the truststore key - it should be set by TruststoreBucketConstruct
        truststore_key = getattr(truststore_bucket, "truststore_key", "bundle.pem")
        print(f"Using truststore key: {truststore_key}")
        print(f"Truststore bucket: {truststore_bucket.bucket.bucket_name}")

        # Grant API Gateway service permissions to read from the truststore bucket
        # API Gateway needs to read the truststore file for mTLS validation
        truststore_bucket.bucket.grant_read(
            iam.ServicePrincipal("apigateway.amazonaws.com")
        )

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
                bucket=truststore_bucket.bucket,
                key=truststore_key,
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
        # For mTLS, we need to include client cert context variables in identity source
        # This ensures the authorizer is invoked even without Authorization header
        self.mtls_lambda_authorizer = apigwv2_auth.HttpLambdaAuthorizer(
            "MTLSCertificateAuthorizer",
            handler=authorizer.authorizer_function,
            response_types=[apigwv2_auth.HttpLambdaResponseType.SIMPLE],
            identity_source=[
                "$context.identity.clientCert.clientCertPem",
                "$context.identity.sourceIp",
            ],  # Include client cert in identity source to ensure authorizer is invoked
            results_cache_ttl=Duration.seconds(0),  # Disable caching for mTLS
        )
        parameter_mapping = apigwv2.ParameterMapping().append_header(
            "X-Client-Cert",
            apigwv2.MappingValue.context_variable("authorizer.clientCertPem"),
        )
        # Create Lambda integration for mTLS API
        self.mtls_lambda_integration = apigwv2_integrations.HttpLambdaIntegration(
            "MTLSLambdaIntegration",
            fastapi_lambda,
            parameter_mapping=parameter_mapping,
        )

        # Add routes to mTLS API (secure endpoints)
        # Test endpoint for mTLS verification
        self.mtls_api.add_routes(
            path="/mtls/test",
            methods=[apigwv2.HttpMethod.GET],
            integration=self.mtls_lambda_integration,
            authorizer=self.mtls_lambda_authorizer,
        )

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
        public_access_log_group = logs.LogGroup(
            self,
            "PublicAccessLogsGroup",
            log_group_name=f"/aws/apigateway/perseus-resource-public-{context['environment_name']}",
            removal_policy=RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.ONE_WEEK,
        )
        public_access_log_group.add_to_resource_policy(
            iam.PolicyStatement(
                principals=[iam.ServicePrincipal("apigateway.amazonaws.com")],
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[
                    public_access_log_group.log_group_arn,
                    f"{public_access_log_group.log_group_arn}:*",
                ],
            )
        )

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

        if self.public_api.default_stage is not None:
            public_cfn_stage = self.public_api.default_stage.node.default_child
            if isinstance(public_cfn_stage, apigwv2.CfnStage):
                public_cfn_stage.access_log_settings = (
                    apigwv2.CfnStage.AccessLogSettingsProperty(
                        destination_arn=public_access_log_group.log_group_arn,
                        format=json.dumps(
                            {
                                "requestId": "$context.requestId",
                                "requestTime": "$context.requestTime",
                                "httpMethod": "$context.httpMethod",
                                "path": "$context.path",
                                "status": "$context.status",
                                "error": "$context.error.message",
                                "protocol": "$context.protocol",
                                "sourceIp": "$context.identity.sourceIp",
                            }
                        ),
                    )
                )

        # Create custom domain for public API
        public_domain_name = (
            f"{context['subdomain']}.{context['hosted_zone_name']}"
            if context["subdomain"]
            else context["hosted_zone_name"]
        )
        self.public_domain = apigwv2.DomainName(
            self,
            "PublicDomain",
            domain_name=public_domain_name,
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
            record_name=context["mtls_subdomain"],
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
            record_name=context["subdomain"] if context["subdomain"] else "@",
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayv2DomainProperties(
                    regional_domain_name=self.public_domain.regional_domain_name,
                    regional_hosted_zone_id=self.public_domain.regional_hosted_zone_id,
                )
            ),
        )

        # Add access logs
        # Read the logging format from logging.json if it exists, otherwise use defaults
        logging_json_path = os.path.join(os.path.dirname(__file__), "logging.json")
        if os.path.exists(logging_json_path):
            with open(logging_json_path, "r") as f:
                logging_format = json.load(f)
        else:
            # Fallback format if logging.json doesn't exist
            logging_format = {
                "apiType": "mtls",
                "domainName": "$context.domainName",
                "httpMethod": "$context.httpMethod",
                "status": "$context.status",
                "requestId": "$context.requestId",
                "requestTime": "$context.requestTime",
                "ip": "$context.identity.sourceIp",
                "routeKey": "$context.routeKey",
                "protocol": "$context.protocol",
                "responseLength": "$context.responseLength",
                # Useful for debugging authorizer behavior:
                "authorizerError": "$context.authorizer.error",
                # These are the client-cert fields (may be empty on OPTIONS, or if using execute-api URL)
                "clientCertPem": "$context.identity.clientCert.clientCertPem",
                "subjectDN": "$context.identity.clientCert.subjectDN",
                "issuerDN": "$context.identity.clientCert.issuerDN",
                "serialNumber": "$context.identity.clientCert.serialNumber",
                "notBefore": "$context.identity.clientCert.validity.notBefore",
                "notAfter": "$context.identity.clientCert.validity.notAfter",
                # What the authorizer returned
                "authorizerProperty": "$context.authorizer.clientCertPem",
            }

        # Convert dict to JSON string for access log format
        access_log_format = json.dumps(logging_format)

        # Access the default stage's L1 CfnStage construct via escape hatch
        # This approach works as documented in the GitHub issue
        from aws_cdk.aws_apigatewayv2 import CfnStage

        default_stage = self.mtls_api.default_stage
        if default_stage:
            # Access the L1 Resource in the L2 Stage
            cfn_stage = default_stage.node.default_child
            if isinstance(cfn_stage, CfnStage):
                # Set access log settings directly on the L1 construct
                # This works because L1 constructs always have the full CloudFormation properties
                cfn_stage.add_property_override(
                    "AccessLogSettings",
                    {
                        "DestinationArn": mtls_access_log_group.log_group_arn,
                        "Format": access_log_format,
                    },
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

        # CfnOutput(
        #     self,
        #     "MTLSApiGatewayAccessLogGroup",
        #     value=self.mtls_access_log_group.log_group_name,
        #     description="mTLS API Gateway Access Log Group",
        # )

        # CfnOutput(
        #     self,
        #     "PublicApiGatewayAccessLogGroup",
        #     value=self.public_access_log_group.log_group_name,
        #     description="Public API Gateway Access Log Group",
        # )
