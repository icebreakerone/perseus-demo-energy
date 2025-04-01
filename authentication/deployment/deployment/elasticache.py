from aws_cdk import aws_ec2 as ec2, aws_elasticache as elasticache, aws_ssm as ssm
from constructs import Construct


class RedisConstruct(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        vpc: ec2.Vpc,
        redis_sg: ec2.SecurityGroup,
        env_name: str,
        **kwargs,
    ):
        super().__init__(scope, id)

        subnet_group = elasticache.CfnSubnetGroup(
            self,
            "RedisSubnetGroup",
            description="Redis subnet group",
            subnet_ids=[subnet.subnet_id for subnet in vpc.private_subnets],
        )

        self.redis = elasticache.CfnCacheCluster(
            self,
            "RedisCluster",
            engine="redis",
            cache_node_type="cache.t3.micro",
            num_cache_nodes=1,
            cache_subnet_group_name=subnet_group.ref,
            vpc_security_group_ids=[redis_sg.security_group_id],
        )
        self.redis_host_param = ssm.StringParameter(
            self,
            "RedisHostParam",
            string_value=self.redis.attr_redis_endpoint_address,
            parameter_name=f"/authentication-service/{env_name}/redis-host",
        )
