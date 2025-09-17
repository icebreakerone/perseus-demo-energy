from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
    aws_s3 as s3,
    CfnOutput,
)
from constructs import Construct


class TruststoreConstruct(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        environment_name: str,
        existing_bucket_name: str,
        truststore_key: str = "bundle.pem",
    ):
        super().__init__(scope, id)

        # Reference the existing S3 bucket from the resource deployment
        self.bucket = s3.Bucket.from_bucket_name(
            self,
            "ExistingTruststoreBucket",
            bucket_name=existing_bucket_name,
        )

        # Create ELB Trust Store using the existing S3 object
        self.trust_store = elbv2.CfnTrustStore(
            self,
            "TrustStore",
            name=f"PerseusAuthenticationTrust-{environment_name}",
            ca_certificates_bundle_s3_bucket=existing_bucket_name,
            ca_certificates_bundle_s3_key=truststore_key,
        )

        # Outputs
        CfnOutput(
            self,
            "TrustStoreArn",
            value=self.trust_store.attr_trust_store_arn,
            description="ELB Trust Store ARN",
        )

        CfnOutput(
            self,
            "TruststoreBucketName",
            value=existing_bucket_name,
            description="Existing Truststore Bucket Name",
        )
