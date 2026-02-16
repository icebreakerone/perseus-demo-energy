from aws_cdk import aws_iam as iam, Stack
from constructs import Construct


class MessagingPolicy(Construct):
    """Creates IAM policy granting read access to the mTLS certificates bucket."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        app_name: str,
        env_name: str,
        s3_bucket_arn: str,
        **kwargs,
    ):
        super().__init__(scope, id, **kwargs)

        stack = Stack.of(self)

        self.policy = iam.ManagedPolicy(
            self,
            "MessagingPolicy",
            managed_policy_name=f"{app_name}-{env_name}-MessagingPolicy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:GetObject",
                        "s3:ListBucket",
                    ],
                    resources=[
                        s3_bucket_arn,
                        f"{s3_bucket_arn}/*",
                    ],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["kms:Decrypt"],
                    resources=[f"arn:aws:kms:{stack.region}:{stack.account}:key/*"],
                    conditions={
                        "StringEquals": {
                            "kms:ViaService": f"s3.{stack.region}.amazonaws.com"
                        }
                    },
                ),
            ],
        )
