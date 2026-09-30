"""
Load balancer access and connection logs, and the Athena tables to query them.

The mTLS listeners run mutual authentication in verify mode, so a connection
whose certificate is refused never reaches the app and is not in its audit log.
The connection log is the only record of it: one line per TLS handshake, with
the client certificate's subject, serial, validity and the verify result.

The table definitions and regexes are AWS's own, from "Query Application Load
Balancer logs" in the Athena user guide, with partition projection by day.
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_athena as athena,
    aws_elasticloadbalancingv2 as elbv2,
    aws_glue as glue,
    aws_s3 as s3,
)
from constructs import Construct

CONNECTION_LOG_COLUMNS = [
    ("time", "string"),
    ("client_ip", "string"),
    ("client_port", "int"),
    ("listener_port", "int"),
    ("tls_protocol", "string"),
    ("tls_cipher", "string"),
    ("tls_handshake_latency", "double"),
    ("leaf_client_cert_subject", "string"),
    ("leaf_client_cert_validity", "string"),
    ("leaf_client_cert_serial_number", "string"),
    ("tls_verify_status", "string"),
    ("conn_trace_id", "string"),
]
CONNECTION_LOG_REGEX = (
    r"([^ ]*) ([^ ]*) ([0-9]*) ([0-9]*) ([A-Za-z0-9.-]*) ([^ ]*) ([-.0-9]*) "
    r'"([^"]*)" ([^ ]*) ([^ ]*) ([^ ]*) ?([^ ]*)?( .*)?'
)

ACCESS_LOG_COLUMNS = [
    ("type", "string"),
    ("time", "string"),
    ("elb", "string"),
    ("client_ip", "string"),
    ("client_port", "int"),
    ("target_ip", "string"),
    ("target_port", "int"),
    ("request_processing_time", "double"),
    ("target_processing_time", "double"),
    ("response_processing_time", "double"),
    ("elb_status_code", "int"),
    ("target_status_code", "string"),
    ("received_bytes", "bigint"),
    ("sent_bytes", "bigint"),
    ("request_verb", "string"),
    ("request_url", "string"),
    ("request_proto", "string"),
    ("user_agent", "string"),
    ("ssl_cipher", "string"),
    ("ssl_protocol", "string"),
    ("target_group_arn", "string"),
    ("trace_id", "string"),
    ("domain_name", "string"),
    ("chosen_cert_arn", "string"),
    ("matched_rule_priority", "string"),
    ("request_creation_time", "string"),
    ("actions_executed", "string"),
    ("redirect_url", "string"),
    ("lambda_error_reason", "string"),
    ("target_port_list", "string"),
    ("target_status_code_list", "string"),
    ("classification", "string"),
    ("classification_reason", "string"),
    ("conn_trace_id", "string"),
]
ACCESS_LOG_REGEX = (
    r"([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) "
    r"([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) "
    r'"([^ ]*) (.*) (- |[^ ]*)" "([^"]*)" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) '
    r'([^ ]*) "([^"]*)" "([^"]*)" "([^"]*)" ([-.0-9]*) ([^ ]*) "([^"]*)" '
    r'"([^"]*)" "([^ ]*)" "([^\s]+?)" "([^\s]+)" "([^ ]*)" "([^ ]*)" '
    r"?([^ ]*)? ?( .*)?"
)

FAILED_HANDSHAKES_QUERY = """-- Connections refused at the load balancer, by client certificate
SELECT
  replace(leaf_client_cert_subject, '"', '') AS subject,
  leaf_client_cert_serial_number AS serial,
  leaf_client_cert_validity AS validity,
  tls_verify_status,
  count(*) AS attempts,
  min(time) AS first_seen,
  max(time) AS last_seen,
  array_agg(DISTINCT client_ip) AS client_ips
FROM {table}
WHERE day >= date_format(current_date - interval '7' day, '%Y/%m/%d')
  AND tls_verify_status <> 'Success'
GROUP BY 1, 2, 3, 4
ORDER BY last_seen DESC
"""

CLIENTS_QUERY = """-- Every client certificate that completed a handshake
SELECT
  replace(leaf_client_cert_subject, '"', '') AS subject,
  leaf_client_cert_serial_number AS serial,
  leaf_client_cert_validity AS validity,
  count(*) AS connections,
  min(time) AS first_seen,
  max(time) AS last_seen
FROM {table}
WHERE day >= date_format(current_date - interval '30' day, '%Y/%m/%d')
  AND tls_verify_status = 'Success'
GROUP BY 1, 2, 3
ORDER BY last_seen DESC
"""

LOAD_BALANCER_ERRORS_QUERY = """-- Requests the load balancer answered with an error, including the
-- target failures an app cannot log itself, such as a Lambda timeout
SELECT
  time, domain_name, request_verb, request_url, elb_status_code,
  target_status_code, lambda_error_reason, classification_reason,
  client_ip, user_agent, conn_trace_id
FROM {table}
WHERE day >= date_format(current_date - interval '7' day, '%Y/%m/%d')
  AND elb_status_code >= 400
ORDER BY time DESC
LIMIT 200
"""


class AlbLogs(Construct):
    """
    A bucket the load balancers write their logs to, with a Glue database and
    Athena workgroup to query them. Call `log()` for each load balancer.
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        app_name: str,
        environment_name: str,
        retention_days: int,
    ):
        super().__init__(scope, id)
        stack = Stack.of(self)
        self.app_name = app_name
        self.environment_name = environment_name

        # Load balancers can only deliver logs to a bucket using S3 managed keys
        self.bucket = s3.Bucket(
            self,
            "Bucket",
            bucket_name=f"perseus-{app_name}-alb-logs-{environment_name}-{stack.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            lifecycle_rules=[
                s3.LifecycleRule(expiration=Duration.days(retention_days))
            ],
            removal_policy=RemovalPolicy.RETAIN,
        )

        self.database_name = f"perseus_{app_name}_{environment_name}_alb".replace(
            "-", "_"
        )
        self.database = glue.CfnDatabase(
            self,
            "Database",
            catalog_id=stack.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name=self.database_name,
                description=f"Load balancer logs for {app_name} ({environment_name})",
            ),
        )

        self.workgroup = athena.CfnWorkGroup(
            self,
            "WorkGroup",
            name=f"perseus-{app_name}-{environment_name}-alb-logs",
            description=f"Queries over the {app_name} load balancer logs",
            recursive_delete_option=True,
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                enforce_work_group_configuration=True,
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    output_location=f"s3://{self.bucket.bucket_name}/athena-results/",
                ),
            ),
        )

    def log(
        self,
        load_balancer: elbv2.ApplicationLoadBalancer,
        name: str,
        connection_logs: bool = False,
    ) -> None:
        """
        Turn on access logs for a load balancer, and connection logs if it
        authenticates clients, with a table over each.
        """
        access_prefix = f"{name}/access"
        load_balancer.log_access_logs(self.bucket, prefix=access_prefix)
        access_table = self._table(
            f"{name}_access_logs", access_prefix, ACCESS_LOG_COLUMNS, ACCESS_LOG_REGEX
        )
        self._query(
            f"{name}-load-balancer-errors",
            f"{self.app_name} {name}: load balancer errors, last 7 days",
            LOAD_BALANCER_ERRORS_QUERY.format(table=access_table),
        )
        if not connection_logs:
            return

        connection_prefix = f"{name}/connection"
        load_balancer.log_connection_logs(self.bucket, prefix=connection_prefix)
        connection_table = self._table(
            f"{name}_connection_logs",
            connection_prefix,
            CONNECTION_LOG_COLUMNS,
            CONNECTION_LOG_REGEX,
        )
        self._query(
            f"{name}-failed-handshakes",
            f"{self.app_name} {name}: refused client certificates, last 7 days",
            FAILED_HANDSHAKES_QUERY.format(table=connection_table),
        )
        self._query(
            f"{name}-clients",
            f"{self.app_name} {name}: client certificates connecting, last 30 days",
            CLIENTS_QUERY.format(table=connection_table),
        )

    def _table(self, table_name: str, prefix: str, columns: list, regex: str) -> str:
        stack = Stack.of(self)
        location = (
            f"s3://{self.bucket.bucket_name}/{prefix}/AWSLogs/{stack.account}/"
            f"elasticloadbalancing/{stack.region}"
        )
        table = glue.CfnTable(
            self,
            f"Table-{table_name}",
            catalog_id=stack.account,
            database_name=self.database_name,
            table_input=glue.CfnTable.TableInputProperty(
                name=table_name,
                table_type="EXTERNAL_TABLE",
                partition_keys=[
                    glue.CfnTable.ColumnProperty(name="day", type="string")
                ],
                parameters={
                    "EXTERNAL": "TRUE",
                    "projection.enabled": "true",
                    "projection.day.type": "date",
                    "projection.day.range": "2026/01/01,NOW",
                    "projection.day.format": "yyyy/MM/dd",
                    "projection.day.interval": "1",
                    "projection.day.interval.unit": "DAYS",
                    "storage.location.template": location + "/${day}",
                },
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    columns=[
                        glue.CfnTable.ColumnProperty(name=column, type=kind)
                        for column, kind in columns
                    ],
                    location=location + "/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format=(
                        "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
                    ),
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.apache.hadoop.hive.serde2.RegexSerDe",
                        parameters={
                            "serialization.format": "1",
                            "input.regex": regex,
                        },
                    ),
                ),
            ),
        )
        table.add_dependency(self.database)
        return table_name

    def _query(self, id: str, name: str, query: str) -> None:
        named_query = athena.CfnNamedQuery(
            self,
            f"Query-{id}",
            name=name,
            database=self.database_name,
            work_group=self.workgroup.name,
            query_string=query,
        )
        named_query.add_dependency(self.database)
        named_query.add_dependency(self.workgroup)
