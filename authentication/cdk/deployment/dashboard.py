"""
One CloudWatch dashboard for both demo apps: who is connecting, with which
certificate, to what, and how it went.

Most widgets query the audit lines the apps write, one per request with
"event": "request" (see api/audit.py in each app). The load balancer widgets
cover what never reaches an app: handshakes refused for a bad certificate, and
failures of the Lambda target itself. Per-certificate detail on refused
handshakes is in the connection logs, queried with Athena.

The resource API is a separate stack, deployed first. Its log group has a fixed
name, and it publishes its load balancer and function names to SSM for this
stack to read.
"""

from aws_cdk import (
    Duration,
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_elasticloadbalancingv2 as elbv2,
    aws_logs as logs,
    aws_ssm as ssm,
)
from constructs import Construct

NAMESPACE = "Perseus/Audit"


def audit_metric_filters(scope: Construct, id: str, log_group: logs.ILogGroup) -> None:
    """
    Count audit lines and record their latency as metrics, so the headline
    numbers and trends need no log scan.
    """
    scope = Construct(scope, id)
    dimensions = {"env": "$.env", "service": "$.service", "outcome": "$.outcome"}
    logs.MetricFilter(
        scope,
        "AuditRequests",
        log_group=log_group,
        metric_namespace=NAMESPACE,
        metric_name="Requests",
        filter_pattern=logs.FilterPattern.string_value("$.event", "=", "request"),
        metric_value="1",
        dimensions=dimensions,
    )
    logs.MetricFilter(
        scope,
        "AuditLatency",
        log_group=log_group,
        metric_namespace=NAMESPACE,
        metric_name="LatencyMs",
        filter_pattern=logs.FilterPattern.string_value("$.event", "=", "request"),
        metric_value="$.latency_ms",
        dimensions={"env": "$.env", "service": "$.service"},
        unit=cloudwatch.Unit.MILLISECONDS,
    )


# Logs Insights queries, as (command, argument) pairs so the same definition
# renders a dashboard widget and a saved query
QUERIES: dict[str, dict] = {
    "who": {
        "title": "Who is using what",
        "filter": 'event = "request" and ispresent(client_application)',
        "stats": (
            "count(*) as requests, count(error) as refused, "
            "latest(@timestamp) as last_seen "
            "by client_application, client_member, service, route"
        ),
        "sort": "last_seen desc",
        "limit": 100,
    },
    "errors": {
        "title": "Recent errors",
        "fields": (
            "@timestamp, service, route, status, error, failure_stage, "
            "client_application, error_description, request_id"
        ),
        "filter": 'event = "request" and status >= 400',
        "sort": "@timestamp desc",
        "limit": 50,
    },
    "failures": {
        "title": "Refused requests by reason and client",
        "filter": 'event = "request" and ispresent(failure_stage)',
        "stats": (
            "count(*) as refused, latest(@timestamp) as last_seen "
            "by failure_stage, client_application, service"
        ),
        "sort": "refused desc",
    },
    "tokens": {
        "title": "Authorisation activity by client",
        "filter": r'event = "request" and service = "authentication" and route like /^\/api\/v1\//',
        "stats": (
            "count(*) as calls, count(error) as refused, "
            "latest(@timestamp) as last_seen by client_application, route, grant_type"
        ),
        "sort": "calls desc",
    },
    "certificates": {
        "title": "Client certificates in use, soonest expiry first",
        "filter": 'event = "request" and ispresent(client_serial)',
        "stats": (
            "min(client_days_to_expiry) as days_left, "
            "latest(client_not_after) as not_after, count(*) as requests, "
            "latest(@timestamp) as last_seen "
            "by client_application, client_member, client_serial, client_issuer"
        ),
        "sort": "days_left asc",
    },
    "latency": {
        "title": "Latency by route (ms)",
        "filter": 'event = "request"',
        "stats": (
            "count(*) as requests, pct(latency_ms, 50) as p50, "
            "pct(latency_ms, 95) as p95, max(latency_ms) as max "
            "by service, route"
        ),
        "sort": "p95 desc",
    },
}

QUERY_ORDER = ("fields", "filter", "stats", "sort", "limit")


def render(query: dict) -> str:
    return "\n| ".join(
        f"{command} {query[command]}" for command in QUERY_ORDER if command in query
    )


class Dashboard(Construct):
    def __init__(
        self,
        scope: Construct,
        id: str,
        environment_name: str,
        authentication_log_group: logs.ILogGroup,
        authentication_mtls_alb: elbv2.ApplicationLoadBalancer,
        authentication_public_alb: elbv2.ApplicationLoadBalancer,
        athena_workgroups: list[str],
    ):
        super().__init__(scope, id)
        stack = Stack.of(self)
        env = environment_name

        resource_log_group_name = f"/perseus/{env}/resource-api"
        audit_metric_filters(self, "AuthenticationMetrics", authentication_log_group)
        audit_metric_filters(
            self,
            "ResourceMetrics",
            logs.LogGroup.from_log_group_name(
                self, "ResourceLogGroup", resource_log_group_name
            ),
        )
        log_group_names = [
            authentication_log_group.log_group_name,
            resource_log_group_name,
        ]

        def resource_parameter(name: str) -> str:
            return ssm.StringParameter.value_for_string_parameter(
                self, f"/perseus/{env}/resource-api/{name}"
            )

        load_balancers = {
            "Authentication mTLS": authentication_mtls_alb.load_balancer_full_name,
            "Authentication public": authentication_public_alb.load_balancer_full_name,
            "Resource mTLS": resource_parameter("mtls-alb-full-name"),
            "Resource public": resource_parameter("public-alb-full-name"),
        }
        mtls_load_balancers = {
            label: name for label, name in load_balancers.items() if "mTLS" in label
        }
        resource_function_name = resource_parameter("function-name")

        def requests(service: str, outcome: str, label: str) -> cloudwatch.Metric:
            return cloudwatch.Metric(
                namespace=NAMESPACE,
                metric_name="Requests",
                dimensions_map={"env": env, "service": service, "outcome": outcome},
                statistic="Sum",
                label=label,
            )

        def load_balancer_metric(
            metric_name: str, load_balancer: str, label: str
        ) -> cloudwatch.Metric:
            return cloudwatch.Metric(
                namespace="AWS/ApplicationELB",
                metric_name=metric_name,
                dimensions_map={"LoadBalancer": load_balancer},
                statistic="Sum",
                label=label,
            )

        def log_table(key: str, width: int = 24, height: int = 8, groups=None):
            query = QUERIES[key]
            return cloudwatch.LogQueryWidget(
                title=query["title"],
                log_group_names=groups or log_group_names,
                query_string=render(query),
                view=cloudwatch.LogQueryVisualizationType.TABLE,
                width=width,
                height=height,
            )

        outcomes = (
            ("success", "Succeeded"),
            ("client_error", "Refused"),
            ("server_error", "Failed"),
        )
        services = (("authentication", "Authentication"), ("resource", "Resource"))
        region = stack.region
        workgroup_names = " or ".join(f"`{workgroup}`" for workgroup in athena_workgroups)
        # Both stages run against the Perseus sandbox trust framework. They share
        # an account, where dashboard names must be unique, so preprod is named
        stage = "prod" if env == "prod" else "preprod"
        dashboard_name = (
            "perseus-sandbox" if stage == "prod" else "perseus-sandbox-preprod"
        )

        dashboard = cloudwatch.Dashboard(
            self,
            "Dashboard",
            dashboard_name=dashboard_name,
            default_interval=Duration.days(1),
        )
        dashboard.add_widgets(
            cloudwatch.TextWidget(
                markdown=(
                    f"# Perseus sandbox demo services ({stage})\n"
                    "Every request that reaches the authentication or resource API "
                    "writes one audit line naming the client certificate. "
                    "A connection whose certificate the load balancer refuses never "
                    "reaches the app, so it is counted under *TLS handshakes refused* "
                    "and listed, with its certificate, by saved queries in Athena. "
                    "To find them:\n\n"
                    f"1. Open Athena in the {region} region\n"
                    "2. Open the query editor\n"
                    f"3. Choose the {workgroup_names} workgroup at the top right\n"
                    "4. Open the **Saved queries** tab"
                ),
                width=24,
                height=5,
            )
        )
        dashboard.add_widgets(
            *(
                cloudwatch.SingleValueWidget(
                    title=f"{title} requests",
                    metrics=[
                        requests(service, outcome, label) for outcome, label in outcomes
                    ],
                    set_period_to_time_range=True,
                    width=8,
                    height=4,
                )
                for service, title in services
            ),
            cloudwatch.SingleValueWidget(
                title="TLS handshakes refused",
                metrics=[
                    load_balancer_metric("ClientTLSNegotiationErrorCount", name, label)
                    for label, name in mtls_load_balancers.items()
                ],
                set_period_to_time_range=True,
                width=8,
                height=4,
            ),
        )
        dashboard.add_widgets(
            *(
                cloudwatch.GraphWidget(
                    title=f"{title} requests by outcome",
                    left=[
                        requests(service, outcome, label) for outcome, label in outcomes
                    ],
                    stacked=True,
                    period=Duration.minutes(5),
                    width=12,
                    height=6,
                )
                for service, title in services
            )
        )
        dashboard.add_widgets(log_table("who", height=9))
        dashboard.add_widgets(
            log_table("failures", width=12),
            log_table("tokens", width=12, groups=[log_group_names[0]]),
        )
        dashboard.add_widgets(log_table("errors"))
        dashboard.add_widgets(log_table("certificates"))
        dashboard.add_widgets(
            log_table("latency", width=12),
            cloudwatch.GraphWidget(
                title="Latency, p95 (ms)",
                left=[
                    cloudwatch.Metric(
                        namespace=NAMESPACE,
                        metric_name="LatencyMs",
                        dimensions_map={"env": env, "service": service},
                        statistic="p95",
                        label=title,
                    )
                    for service, title in services
                ],
                period=Duration.minutes(5),
                width=12,
                height=8,
            ),
        )
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Load balancer: refused handshakes and its own errors",
                left=[
                    load_balancer_metric(
                        "ClientTLSNegotiationErrorCount", name, f"{label} TLS refused"
                    )
                    for label, name in mtls_load_balancers.items()
                ]
                + [
                    load_balancer_metric("HTTPCode_ELB_5XX_Count", name, f"{label} 5xx")
                    for label, name in load_balancers.items()
                ],
                period=Duration.minutes(5),
                width=12,
                height=6,
            ),
            cloudwatch.GraphWidget(
                title="Resource API Lambda",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/Lambda",
                        metric_name=metric_name,
                        dimensions_map={"FunctionName": resource_function_name},
                        statistic="Sum",
                    )
                    for metric_name in ("Invocations", "Errors", "Throttles")
                ],
                right=[
                    cloudwatch.Metric(
                        namespace="AWS/Lambda",
                        metric_name="Duration",
                        dimensions_map={"FunctionName": resource_function_name},
                        statistic="p95",
                    )
                ],
                period=Duration.minutes(5),
                width=12,
                height=6,
            ),
        )

        # The same queries, saved for use in Logs Insights
        for key, query in QUERIES.items():
            logs.QueryDefinition(
                self,
                f"Query-{key}",
                query_definition_name=f"Perseus/{env}/{query['title']}",
                query_string=logs.QueryString(
                    fields=[query["fields"]] if "fields" in query else None,
                    filter_statements=[query["filter"]],
                    stats=query.get("stats"),
                    sort=query.get("sort"),
                    limit=query.get("limit"),
                ),
                log_groups=[
                    logs.LogGroup.from_log_group_name(
                        self, f"Group-{key}-{index}", name
                    )
                    for index, name in enumerate(
                        [log_group_names[0]] if key == "tokens" else log_group_names
                    )
                ],
            )
