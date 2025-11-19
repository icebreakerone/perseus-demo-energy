import os
from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3_deployment,
    RemovalPolicy,
    CfnOutput,
)
from constructs import Construct


class TruststoreBucketConstruct(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        environment_name: str,
        truststore_file_path: str | None = None,
    ):
        super().__init__(scope, id)

        # Create S3 bucket for truststore
        self.bucket = s3.Bucket(
            self,
            "TruststoreBucket",
            bucket_name=f"perseus-resource-truststore-{environment_name}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        print(f"Truststore file path: {truststore_file_path}")
        # Upload truststore file if provided
        if truststore_file_path and os.path.exists(truststore_file_path):
            print(f"Uploading truststore file from {truststore_file_path}")
            truststore_dir = os.path.dirname(truststore_file_path)
            truststore_filename = os.path.basename(truststore_file_path)
            print(f"Truststore directory: {truststore_dir}")
            print(f"Truststore filename: {truststore_filename}")
            self.bucket_deployment = s3_deployment.BucketDeployment(
                self,
                "TruststoreDeployment",
                sources=[s3_deployment.Source.asset(truststore_dir)],
                destination_bucket=self.bucket,
                destination_key_prefix="",
                # Only upload the specific truststore file
                exclude=["*"],
                include=[truststore_filename],
            )
            self.truststore_key = truststore_filename
            print(
                f"Truststore will be uploaded to s3://{self.bucket.bucket_name}/{self.truststore_key}"
            )
        else:
            # Fallback: create a placeholder file or use default
            self.truststore_key = "truststore.pem"
            # self.bucket_deployment = None
            print(
                f"Warning: Truststore file not found at {truststore_file_path}. Using default key: {self.truststore_key}"
            )
        CfnOutput(
            self,
            "TruststoreBucketName",
            value=self.bucket.bucket_name,
            description="Truststore Bucket Name",
        )
        CfnOutput(
            self,
            "TruststoreBucketArn",
            value=self.bucket.bucket_arn,
            description="Truststore Bucket ARN",
        )
