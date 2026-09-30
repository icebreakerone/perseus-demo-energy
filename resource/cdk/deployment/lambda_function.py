import os
from aws_cdk import (
    aws_lambda as lambda_,
    aws_iam as iam,
    Duration,
    aws_ecr_assets as ecr_assets,
    aws_logs as logs,
    RemovalPolicy,
)
from constructs import Construct

# Log retention by the number of days in the deployment context, which the
# load balancer log bucket's lifecycle also uses
RETENTION = {
    30: logs.RetentionDays.ONE_MONTH,
    90: logs.RetentionDays.THREE_MONTHS,
    365: logs.RetentionDays.ONE_YEAR,
}


class FastAPILambdaConstruct(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        environment_name: str,
        ssm_policy: iam.ManagedPolicy,
        environment_variables: dict,
        log_retention_days: int,
    ):
        super().__init__(scope, id)

        # Get the directory containing this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        resource_dir = os.path.dirname(os.path.dirname(current_dir))

        # Create Docker image asset
        docker_image = ecr_assets.DockerImageAsset(
            self,
            "FastAPILambdaImage",
            directory=resource_dir,
            file="Dockerfile.lambda",
            platform=ecr_assets.Platform.LINUX_AMD64,
        )

        # Named, so the dashboard in the authentication stack can query it.
        # Without this Lambda creates /aws/lambda/<function> itself, kept forever.
        self.log_group = logs.LogGroup(
            self,
            "LogGroup",
            log_group_name=f"/perseus/{environment_name}/resource-api",
            retention=RETENTION[log_retention_days],
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Create Lambda function using container image
        self.function = lambda_.Function(
            self,
            "FastAPILambda",
            runtime=lambda_.Runtime.FROM_IMAGE,
            handler=lambda_.Handler.FROM_IMAGE,
            code=lambda_.Code.from_ecr_image(
                repository=docker_image.repository,
                tag_or_digest=docker_image.image_tag,
            ),
            environment=environment_variables,
            timeout=Duration.seconds(30),
            memory_size=512,
            log_group=self.log_group,
        )

        # Attach SSM policy
        if self.function.role:
            self.function.role.add_managed_policy(ssm_policy)
        else:
            raise RuntimeError("No role found for Lambda function")

        # Add additional permissions for S3
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:ListBucket",
                ],
                resources=[
                    "arn:aws:s3:::perseus-demo-energy-certificate-store",
                    "arn:aws:s3:::perseus-demo-energy-certificate-store/*",
                ],
            )
        )

        self.log_group.grant_write(self.function)
