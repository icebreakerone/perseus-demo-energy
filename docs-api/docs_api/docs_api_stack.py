import os
import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3_deployment,
    aws_route53 as route53,
    aws_route53_targets as targets,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    RemovalPolicy,
)

from constructs import Construct

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


class DocsApiStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        domain_name="docs.preprod.perseus-demo-authentication.ib1.org",
        folder="authentication",
        **kwargs,
    ):
        super().__init__(scope, id, **kwargs)
        docs_subdomain = domain_name[0 : domain_name.index("perseus") - 1]
        zone_name = domain_name[len(docs_subdomain) + 1 :]
        # Create S3 bucket
        bucket = s3.Bucket(
            self,
            "DocsBucket",
            bucket_name=domain_name,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
        )
        s3_deployment.BucketDeployment(
            self,
            "DeployDocs",
            sources=[
                s3_deployment.Source.asset(f"{ROOT_DIR}/{folder}/output")
            ],  # Folder with docs.html & openapi.json
            destination_bucket=bucket,
        )
        origin_access_identity = cloudfront.OriginAccessIdentity(
            self, "OAI", comment="Connects CF with S3"
        )

        bucket.grant_read(origin_access_identity)

        certificate = acm.Certificate(
            self,
            "SiteCertificate",
            domain_name=domain_name,
            validation=acm.CertificateValidation.from_dns(),
        )

        distribution = cloudfront.Distribution(
            self,
            "SiteDistribution",
            default_root_object="index.html",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(
                    bucket, origin_access_identity=origin_access_identity
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
            domain_names=[domain_name],
            certificate=certificate,
        )
        # Deploy static files to S3

        hosted_zone = route53.HostedZone.from_lookup(
            self, "HostedZone", domain_name=zone_name
        )
        route53.ARecord(
            self,
            "AliasRecord",
            zone=hosted_zone,
            record_name=docs_subdomain,
            target=route53.RecordTarget.from_alias(
                targets.CloudFrontTarget(distribution)
            ),
        )
        cdk.CfnOutput(
            self,
            "CloudFrontURL",
            value=f"https://{distribution.distribution_domain_name}",
            description="The CloudFront distribution URL",
        )
