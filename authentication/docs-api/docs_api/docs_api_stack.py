from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3_deployment,
    aws_route53 as route53,
    aws_route53_targets as targets,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
)

from constructs import Construct


class DocsApiStack(core.Stack):
    def __init__(self, scope: Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        # Create S3 bucket
        bucket = s3.Bucket(
            self,
            "DocsBucket",
            website_index_document="docs.html",
            public_read_access=True,
        )

        # Deploy static files to S3
        s3_deployment.BucketDeployment(
            self,
            "DeployDocs",
            sources=[
                s3_deployment.Source.asset("path_to_exported_docs")
            ],  # Folder with docs.html & openapi.json
            destination_bucket=bucket,
        )
        cert = acm.Certificate(
            self,
            "Certificate",
            domain_name="docs.example.com",
            validation=acm.CertificateValidation.from_dns(hosted_zone),
        )
        # Create CloudFront distribution
        distribution = cloudfront.Distribution(
            self,
            domain_names=["docs.example.com"],
            "DocsDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket)
            ),
            certificate=cert,
            origins=[origins.S3Origin(bucket), ],
        )

        # Custom domain for docs.example.com
        hosted_zone = route53.HostedZone.from_lookup(
            self, "HostedZone", domain_name="example.com"
        )
        

        distribution.add_behavior("/", origins.S3Origin(bucket))


        # Route 53 DNS Record
        route53.ARecord(
            self,
            "AliasRecord",
            zone=hosted_zone,
            record_name="docs",
            target=route53.RecordTarget.from_alias(
                targets.CloudFrontTarget(distribution)
            ),
        )
