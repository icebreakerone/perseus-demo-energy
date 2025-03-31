from aws_cdk import aws_ec2 as ec2
from constructs import Construct


class NetworkConstruct(Construct):
    def __init__(self, scope: Construct, id: str, environment_name: str):
        super().__init__(scope, id)

        self.vpc = ec2.Vpc(
            self,
            f"AuthenticationVpc-{environment_name}",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name=f"EDP-{environment_name}-PrivateSubnets",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=28,
                ),
                ec2.SubnetConfiguration(
                    name="Public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24
                ),
            ],
        )

        self.vpc.add_interface_endpoint(
            f"{environment_name}-SSMEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SSM,
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
