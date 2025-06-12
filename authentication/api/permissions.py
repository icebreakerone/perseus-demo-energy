import datetime
from typing import Optional

import boto3

from . import models
from . import conf
from .exceptions import PermissionStorageError
from .logger import get_logger

logger = get_logger()


def get_dynamodb_resource():
    if conf.ENV == "local":
        return boto3.resource(
            "dynamodb",
            endpoint_url="http://dynamodb-local:8000",
            region_name="eu-west-2",
            aws_access_key_id="fakeAccessKey",
            aws_secret_access_key="fakeSecretKey",
        )
    else:
        return boto3.resource("dynamodb")


def ensure_table_exists(table_name: str):
    db = get_dynamodb_resource()
    existing_tables = db.meta.client.list_tables()["TableNames"]

    if table_name not in existing_tables:
        db.create_table(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "account", "KeyType": "HASH"},
                {"AttributeName": "client", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "account", "AttributeType": "S"},
                {"AttributeName": "client", "AttributeType": "S"},
                {"AttributeName": "refreshToken", "AttributeType": "S"},
                {"AttributeName": "evidenceId", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "refresh-token-index",
                    "KeySchema": [
                        {"AttributeName": "refreshToken", "KeyType": "HASH"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                },
                {
                    "IndexName": "evidence-id-index",
                    "KeySchema": [
                        {"AttributeName": "evidenceId", "KeyType": "HASH"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        logger.info(f"Creating table {table_name}...")
        db.Table(table_name).wait_until_exists()
        logger.info("Table ready!")


def write_permission(permission: models.Permission):
    ensure_table_exists(conf.DYNAMODB_TABLE)
    db = get_dynamodb_resource()
    table = db.Table(conf.DYNAMODB_TABLE)

    item = permission.model_dump()
    table.put_item(Item=item)
    logger.info(
        f"Permission stored for account={permission.account} + client={permission.client}"
    )


def get_permission(account: str, client: str) -> Optional[models.Permission]:
    db = get_dynamodb_resource()
    table = db.Table(conf.DYNAMODB_TABLE)

    response = table.get_item(Key={"account": account, "client": client})
    item = response.get("Item")
    if not item:
        logger.info(f"Permission not found: {account} + {client}")
        return None

    return models.Permission(**item)


def get_permission_by_token(refresh_token: str) -> models.Permission | None:
    db = get_dynamodb_resource()
    table = db.Table(conf.DYNAMODB_TABLE)

    response = table.query(
        IndexName="refresh-token-index",
        KeyConditionExpression="refreshToken = :pid",
        ExpressionAttributeValues={":pid": str(refresh_token)},
    )

    items = response.get("Items", [])
    if not items:
        return None

    return models.Permission(**items[0])


def get_permission_by_evidence_id(evidence_id: str) -> models.Permission | None:
    db = get_dynamodb_resource()
    table = db.Table(conf.DYNAMODB_TABLE)

    response = table.query(
        IndexName="evidence-id-index",
        KeyConditionExpression="evidenceId = :pid",
        ExpressionAttributeValues={":pid": str(evidence_id)},
    )

    items = response.get("Items", [])
    if not items:
        return None

    return models.Permission(**items[0])


def token_to_permission(
    decoded_token: dict,
    refresh_token: str,
) -> models.Permission:
    return models.Permission(
        oauthIssuer=decoded_token["iss"],
        client=decoded_token["client_id"],
        license=decoded_token["scp"][0],
        account=decoded_token["sub"],
        lastGranted=datetime.datetime.fromtimestamp(decoded_token["iat"]),
        expires=datetime.datetime.fromtimestamp(decoded_token["exp"]),
        refreshToken=refresh_token,
        revoked=None,
        dataAvailableFrom=datetime.datetime.now(datetime.timezone.utc),
        tokenIssuedAt=datetime.datetime.fromtimestamp(decoded_token["iat"]),
        tokenExpires=datetime.datetime.fromtimestamp(decoded_token["exp"]),
    )


def store_permission(decoded_token: dict, refresh_token: str) -> models.Permission:
    """
    Store the permission in the database.

    Args:
        decoded_token (dict): The decoded JWT token containing the user information.
        permission (Permission): The permission object to be stored.

    Raises:
        PermissionStorageError: If there is an error while storing the permission.
    """
    permission = token_to_permission(decoded_token, refresh_token)
    try:
        # Store the permission in the database
        write_permission(permission)
    except Exception as e:
        raise PermissionStorageError(f"Error storing permission: {str(e)}")
    return permission
