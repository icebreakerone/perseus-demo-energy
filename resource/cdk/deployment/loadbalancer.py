from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_ec2 as ec2,
    aws_route53 as route53,
    aws_route53_targets as targets,
    aws_lambda as lambda_,
    aws_iam as iam,
    Stack,
)
from constructs import Construct
from models import Context


class LoadBalancer(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        vpc: ec2.Vpc,
        context: Context,
        trust_store: elbv2.CfnTrustStore,
        lambda_function: lambda_.Function,
    ):
        super().__init__(scope, id)

        # ========== mTLS Target Group (Lambda) ==========
        # For Lambda targets, we don't specify port or VPC in the target group
        # Lambda targets are invoked via AWS service integration, not network
        self.mtls_target_group = elbv2.ApplicationTargetGroup(
            self,
            "MtlsLambdaTargetGroup",
            target_type=elbv2.TargetType.LAMBDA,
            # Note: Lambda targets don't use port, vpc, or health_check
            # Health checks for Lambda are handled differently
        )

        # Add Lambda function as target
        self.mtls_target_group.add_target(elbv2_targets.LambdaTarget(lambda_function))

        # Grant ALB permission to invoke Lambda
        lambda_function.grant_invoke(
            iam.ServicePrincipal("elasticloadbalancing.amazonaws.com")
        )

        # ========== Public Target Group (Lambda) ==========
        self.public_target_group = elbv2.ApplicationTargetGroup(
            self,
            "PublicLambdaTargetGroup",
            target_type=elbv2.TargetType.LAMBDA,
        )

        # Add Lambda function as target
        self.public_target_group.add_target(elbv2_targets.LambdaTarget(lambda_function))

        # ========== mTLS ALB ==========
        self.mtls_alb_sg = ec2.SecurityGroup(self, "MTLSAlbSG", vpc=vpc)

        self.mtls_alb_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "Allow HTTPS traffic"
        )

        mtls_alb = elbv2.ApplicationLoadBalancer(
            self,
            "MTLSAlb",
            vpc=vpc,
            internet_facing=True,
            security_group=self.mtls_alb_sg,
        )

        elbv2.CfnListener(
            self,
            "MTLSHTTPSListener",
            certificates=[
                {
                    "certificateArn": f"arn:aws:acm:{Stack.of(self).region}:{Stack.of(self).account}:certificate/{context['mtls_certificate']}"  # type: ignore
                }
            ],
            default_actions=[
                {
                    "type": "forward",
                    "targetGroupArn": self.mtls_target_group.target_group_arn,
                }
            ],
            load_balancer_arn=mtls_alb.load_balancer_arn,
            port=443,
            protocol="HTTPS",
            ssl_policy="ELBSecurityPolicy-TLS-1-2-2017-01",
            mutual_authentication={
                "mode": "verify",
                "trustStoreArn": trust_store.attr_trust_store_arn,
            },
        )

        # ========== Public ALB ==========
        self.public_alb_sg = ec2.SecurityGroup(self, "PublicAlbSG", vpc=vpc)
        self.public_alb_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "Allow HTTPS traffic"
        )

        public_alb = elbv2.ApplicationLoadBalancer(
            self,
            "PublicAlb",
            vpc=vpc,
            internet_facing=True,
            security_group=self.public_alb_sg,
        )

        elbv2.CfnListener(
            self,
            "PublicHTTPSListener",
            certificates=[
                {
                    "certificateArn": f"arn:aws:acm:{Stack.of(self).region}:{Stack.of(self).account}:certificate/{context['certificate']}"  # type: ignore
                }
            ],
            default_actions=[
                {
                    "type": "forward",
                    "targetGroupArn": self.public_target_group.target_group_arn,
                }
            ],
            load_balancer_arn=public_alb.load_balancer_arn,
            port=443,
            protocol="HTTPS",
            ssl_policy="ELBSecurityPolicy-TLS-1-2-2017-01",
        )

        # ========== Route53 DNS Records ==========
        hosted_zone = route53.HostedZone.from_lookup(
            self, "HostedZone", domain_name=context["hosted_zone_name"]
        )

        # mTLS domain record
        route53.ARecord(
            self,
            "MTLSALBAliasRecord",
            zone=hosted_zone,
            record_name=context["mtls_subdomain"],  # e.g., preprod.mtls.example.org
            target=route53.RecordTarget.from_alias(
                targets.LoadBalancerTarget(mtls_alb)
            ),
        )

        # Public domain record
        public_record_name = context["subdomain"] if context["subdomain"] else "@"
        route53.ARecord(
            self,
            "PublicALBAliasRecord",
            zone=hosted_zone,
            record_name=public_record_name,  # e.g., preprod.example.org or @
            target=route53.RecordTarget.from_alias(
                targets.LoadBalancerTarget(public_alb)
            ),
        )

        # Optional: expose ALB DNS names as class properties
        self.mtls_alb_dns = mtls_alb.load_balancer_dns_name
        self.public_alb_dns = public_alb.load_balancer_dns_name
