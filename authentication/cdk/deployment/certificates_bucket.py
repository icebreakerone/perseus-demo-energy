from aws_cdk import (
    aws_s3 as s3,
    Stack,
    RemovalPolicy,
)
from constructs import Construct


class CertificatesBucket(Construct):
    """Creates an S3 bucket for storing mTLS client certificates."""

    def __init__(self, scope: Construct, id: str, environment_name: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        stack = Stack.of(self)
        self.bucket = s3.Bucket(
            self,
            "CertificatesBucket",
            bucket_name=f"auth-service-certs-{environment_name}-{stack.account}-{stack.region}",
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            auto_delete_objects=False,
            removal_policy=RemovalPolicy.RETAIN,
        )
