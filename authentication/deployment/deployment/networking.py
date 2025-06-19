from aws_cdk import aws_ec2 as ec2
from constructs import Construct


class NetworkConstruct(Construct):
    def __init__(self, scope: Construct, id: str, environment_name: str):
        super().__init__(scope, id)

        self.vpc = ec2.Vpc(
            self,
            f"AuthenticationVpc-{environment_name}",
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name=f"EDP-{environment_name}-PrivateSubnets",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=28,
                ),
                ec2.SubnetConfiguration(
                    name=f"EDP-{environment_name}-PublicSubnets",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=28,
                ),
            ],
        )

        self.vpc.add_interface_endpoint(
            f"{environment_name}-SSMEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SSM,
        )

        self.vpc.add_interface_endpoint(
            f"{environment_name}-CloudWatchLogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
        )

        self.vpc.add_interface_endpoint(
            f"{environment_name}-ECRDockerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
        )

        self.vpc.add_interface_endpoint(
            f"{environment_name}-ECREndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
        )

        self.redis_sg = ec2.SecurityGroup(
            self, f"{environment_name}-RedisSG", vpc=self.vpc
        )
        self.ecs_sg = ec2.SecurityGroup(self, f"{environment_name}-EcsSG", vpc=self.vpc)

        self.redis_sg.add_ingress_rule(
            peer=self.ecs_sg,
            connection=ec2.Port.tcp(6379),
            description="Allow ECS tasks to access Redis",
        )

        self.ecs_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(self.vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443),
            description="Allow ECS tasks to access VPC endpoints",
        )

        self.ecs_sg.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(443),
            description="Allow ECS tasks to access S3, DynamoDB, and external HTTPS APIs",
        )

        self.ecs_sg.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(80),
            description="Allow ECS tasks to access external HTTP APIs",
        )
