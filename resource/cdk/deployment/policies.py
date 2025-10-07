from aws_cdk import aws_iam as iam
from constructs import Construct


class SSMPermissionsConstruct(Construct):
    def __init__(self, scope: Construct, id: str, app_name: str, env_name: str):
        super().__init__(scope, id)
        self.policy = iam.ManagedPolicy(
            self,
            "SSMAccessPolicy",
            managed_policy_name=f"{app_name}-{env_name}-SSMReadPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=["ssm:GetParameter", "ssm:GetParameters"],
                    resources=[
                        f"arn:aws:ssm:{scope.region}:{scope.account}:parameter/copilot/{app_name}/{env_name}/*"  # type: ignore[attr-defined]
                    ],
                ),
                iam.PolicyStatement(
                    actions=["kms:Decrypt"],
                    resources=[f"arn:aws:kms:{scope.region}:{scope.account}:key/*"],  # type: ignore[attr-defined]
                    conditions={
                        "StringEquals": {
                            "aws:ResourceTag/copilot-application": app_name,
                            "aws:ResourceTag/copilot-environment": env_name,
                        }
                    },
                ),
                iam.PolicyStatement(
                    actions=["s3:GetObject", "s3:ListBucket"],
                    resources=[
                        "arn:aws:s3:::perseus-demo-energy-certificate-store",
                        "arn:aws:s3:::perseus-demo-energy-certificate-store/*",
                    ],
                ),
            ],
        )
