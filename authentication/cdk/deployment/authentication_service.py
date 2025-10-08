from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_logs as logs,
    aws_iam as iam,
    aws_ecr_assets as ecr_assets,
    aws_elasticloadbalancingv2 as elbv2,
    aws_dynamodb as dynamodb,
)
from constructs import Construct


class AuthenticationAPIServiceConstruct(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        vpc: ec2.Vpc,
        ssm_policy: iam.ManagedPolicy,
        environment: dict,
        ecs_sg: ec2.SecurityGroup,
        mtls_target_group: elbv2.ApplicationTargetGroup,
        public_target_group: elbv2.ApplicationTargetGroup,
        mtls_alb_sg: ec2.SecurityGroup,
        public_alb_sg: ec2.SecurityGroup,
        table: dynamodb.Table,
    ):
        super().__init__(scope, id)

        cluster = ecs.Cluster(self, "AuthenticationAPICluster", vpc=vpc)
        log_group = logs.LogGroup(self, "AuthenticationAPILogGroup")
        task_def = ecs.FargateTaskDefinition(self, "TaskDef")
        task_def.task_role.add_managed_policy(ssm_policy)
        task_def.task_role.add_managed_policy(  # For exec
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonSSMManagedInstanceCore"
            )
        )
        table.grant_read_write_data(task_def.task_role)
        # Add ListTables permission for DynamoDB operations
        task_def.task_role.add_to_principal_policy(
            iam.PolicyStatement(
                actions=["dynamodb:ListTables"],
                resources=["*"],  # ListTables requires * resource
                effect=iam.Effect.ALLOW,
            )
        )
        container = task_def.add_container(
            "AuthenticationAPIContainer",
            image=ecs.ContainerImage.from_asset(
                "../", platform=ecr_assets.Platform.LINUX_AMD64
            ),
            logging=ecs.LogDriver.aws_logs(
                stream_prefix="AuthenticationAPI", log_group=log_group
            ),
            environment=environment,
        )
        container.add_port_mappings(ecs.PortMapping(container_port=8080))

        self.service = ecs.FargateService(
            self,
            "AuthenticationAPIService",
            cluster=cluster,
            task_definition=task_def,
            desired_count=1,
            assign_public_ip=True,
            security_groups=[ecs_sg],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            enable_execute_command=True,
        )
        self.service.attach_to_application_target_group(mtls_target_group)
        self.service.attach_to_application_target_group(public_target_group)
        ecs_sg.add_ingress_rule(mtls_alb_sg, ec2.Port.tcp(8080))
        ecs_sg.add_ingress_rule(public_alb_sg, ec2.Port.tcp(8080))
