from aws_cdk import (
    aws_certificatemanager as acm,
    aws_elasticloadbalancingv2 as elbv2,
    aws_ec2 as ec2,
    aws_route53 as route53,
    aws_route53_targets as targets,
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
    ):
        super().__init__(scope, id)

        # ========== Names and certificates ==========
        zone_name = context["hosted_zone_name"]
        mtls_domain = f"{context['mtls_subdomain']}.{zone_name}"
        public_domain = (
            f"{context['subdomain']}.{zone_name}" if context["subdomain"] else zone_name
        )

        hosted_zone = route53.HostedZone.from_lookup(
            self, "HostedZone", domain_name=context["hosted_zone_name"]
        )

        # The Baseline TLS Configuration specification requires server
        # certificates to use ECDSA with P-256 or P-384, and forbids wildcard
        # names. ACM issues and renews these, so no ARN is carried in context.
        mtls_certificate = acm.Certificate(
            self,
            "MTLSCertificate",
            domain_name=mtls_domain,
            validation=acm.CertificateValidation.from_dns(hosted_zone),
            key_algorithm=acm.KeyAlgorithm.EC_PRIME256_V1,
        )
        public_certificate = acm.Certificate(
            self,
            "PublicCertificate",
            domain_name=public_domain,
            validation=acm.CertificateValidation.from_dns(hosted_zone),
            key_algorithm=acm.KeyAlgorithm.EC_PRIME256_V1,
        )

        self.mtls_target_group = elbv2.ApplicationTargetGroup(
            self,
            "MtlsTargetGroup",
            vpc=vpc,
            port=8080,
            target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(path="/"),
        )

        self.public_target_group = elbv2.ApplicationTargetGroup(
            self,
            "PublicTargetGroup",
            vpc=vpc,
            port=8080,
            target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(path="/"),
        )

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
                {"certificateArn": mtls_certificate.certificate_arn}
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
            ssl_policy="ELBSecurityPolicy-TLS13-1-3-2021-06",
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
                {"certificateArn": public_certificate.certificate_arn}
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
            ssl_policy="ELBSecurityPolicy-TLS13-1-3-2021-06",
        )

        # ========== Route53 DNS Records ==========
        # mTLS domain record
        route53.ARecord(
            self,
            "MTLSALBAliasRecord",
            zone=hosted_zone,
            record_name=context["mtls_subdomain"],  # e.g., mtls.example.org
            target=route53.RecordTarget.from_alias(
                targets.LoadBalancerTarget(mtls_alb)
            ),
        )

        # Public domain record
        route53.ARecord(
            self,
            "PublicALBAliasRecord",
            zone=hosted_zone,
            record_name=context["subdomain"],  # e.g., api.example.org
            target=route53.RecordTarget.from_alias(
                targets.LoadBalancerTarget(public_alb)
            ),
        )

        # Optional: expose ALB DNS names as class properties
        self.mtls_alb_dns = mtls_alb.load_balancer_dns_name
        self.public_alb_dns = public_alb.load_balancer_dns_name
