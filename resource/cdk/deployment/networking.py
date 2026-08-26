from aws_cdk import aws_ec2 as ec2
from constructs import Construct


class NetworkConstruct(Construct):
    def __init__(self, scope: Construct, id: str, environment_name: str):
        super().__init__(scope, id)

        # Create VPC with public subnets for ALB
        # ALB requires at least 2 availability zones
        # Lambda doesn't need to be in VPC (ALB invokes Lambda via service integration)
        self.vpc = ec2.Vpc(
            self,
            f"ResourceVpc-{environment_name}",
            max_azs=2,  # ALB requires at least 2 AZs
            nat_gateways=0,  # No NAT needed since Lambda is outside VPC
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name=f"Resource-{environment_name}-PublicSubnets",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=28,  # /28 gives 16 IPs per subnet (enough for ALB)
                ),
            ],
        )

        # No VPC endpoints: the only resource in this VPC is the ALB, and the
        # Lambda runs outside the VPC, so nothing here calls AWS APIs privately.
        # Add endpoints back if the Lambda is ever moved into the VPC.

        # Security group for ALB (will be created in loadbalancer.py)
        # This is just a placeholder - actual security groups are created in LoadBalancer construct
        # But we could create them here if needed for consistency
