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

        # Optional: Add VPC endpoints for AWS services if Lambda needs to access them
        # These can reduce data transfer costs and improve security
        # S3 Gateway endpoint (free, no ENI needed)
        self.vpc.add_gateway_endpoint(
            f"{environment_name}-S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
        )

        # Interface endpoints for services that Lambda might use
        # (Only needed if Lambda is in VPC, which we're not doing for simplicity)
        # But adding them for future flexibility and cost optimization
        self.vpc.add_interface_endpoint(
            f"{environment_name}-SSMEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SSM,
        )

        self.vpc.add_interface_endpoint(
            f"{environment_name}-CloudWatchLogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
        )

        # Security group for ALB (will be created in loadbalancer.py)
        # This is just a placeholder - actual security groups are created in LoadBalancer construct
        # But we could create them here if needed for consistency
