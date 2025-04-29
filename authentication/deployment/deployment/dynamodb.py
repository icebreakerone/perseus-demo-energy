from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2, RemovalPolicy
from constructs import Construct


class DynamoDBConstruct(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        vpc: ec2.Vpc,
        env_name: str,
        **kwargs,
    ):
        super().__init__(scope, id, **kwargs)

        # Create the DynamoDB table
        self.table = dynamodb.Table(
            self,
            "AuthenticationTable",
            table_name=f"permissions-{env_name}",
            partition_key=dynamodb.Attribute(
                name="account", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="client", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,  # Change to RETAIN for production
        )
        self.table.add_global_secondary_index(
            index_name="refresh-token-index",
            partition_key=dynamodb.Attribute(
                name="refreshToken", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        self.table.add_global_secondary_index(
            index_name="evidence-id-index",
            partition_key=dynamodb.Attribute(
                name="evidenceId", type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        # Add VPC endpoint for DynamoDB
        vpc.add_gateway_endpoint(
            "DynamoDBVpcEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
        )
