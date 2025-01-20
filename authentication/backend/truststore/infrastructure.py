import os

from constructs import Construct
import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3_deployment,
    Stack,
)


DIRNAME = os.path.dirname(os.path.realpath(__file__))


class Truststore(Construct):

    def __init__(self, scope: Construct, id_: str, **kwargs) -> None:
        super().__init__(scope, id_, **kwargs)
        self.bucket = s3.Bucket(
            self,
            "TruststoreBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,  # use S3-managed encryption
            bucket_name=f"edp-truststore-bucket-prod",
            auto_delete_objects=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        s3_deployment.BucketDeployment(
            self,
            "TruststoreDeployment",
            sources=[s3_deployment.Source.asset(f"{DIRNAME}/certs")],
            destination_bucket=self.bucket,
        )
        cdk.CfnOutput(
            self,
            "S3Bucket",
            export_name="EDPTruststoreBucket",
            value=self.bucket.bucket_name,
        )
