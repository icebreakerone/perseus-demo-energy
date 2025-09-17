import os
from aws_cdk import aws_lambda as lambda_, aws_iam as iam, Duration
from constructs import Construct


class CertificateAuthorizerConstruct(Construct):
    def __init__(self, scope: Construct, id: str, environment_name: str):
        super().__init__(scope, id)

        # Get the directory containing this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        lambda_code_dir = os.path.join(os.path.dirname(current_dir), "lambda_code")

        # Lambda function for certificate authorizer
        self.authorizer_function = lambda_.Function(
            self,
            "CertificateAuthorizer",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="lambda_authorizer.handler",
            code=lambda_.Code.from_asset(lambda_code_dir),
            environment={
                "ENVIRONMENT_NAME": environment_name,
            },
            timeout=Duration.seconds(30),
            memory_size=256,
        )

        # Add CloudWatch logs permission
        self.authorizer_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["*"],
            )
        )
