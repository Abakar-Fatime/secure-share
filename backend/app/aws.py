"""boto3 clients. Endpoint override lets the same code run against a local moto server."""

from functools import lru_cache

import boto3
from botocore.config import Config

from .config import get_settings


def _kwargs() -> dict:
    s = get_settings()
    kw: dict = {"region_name": s.aws_region}
    if s.aws_endpoint_url:
        kw["endpoint_url"] = s.aws_endpoint_url
    return kw


@lru_cache
def dynamodb_table():
    return boto3.resource("dynamodb", **_kwargs()).Table(get_settings().table_name)


def _s3(endpoint: str | None):
    s = get_settings()
    if endpoint is None:
        # Regional, virtual-hosted URLs (https://<bucket>.s3.<region>.amazonaws.com/...)
        endpoint = f"https://s3.{s.aws_region}.amazonaws.com"
        config = Config(signature_version="s3v4", s3={"addressing_style": "virtual"})
    else:
        config = Config(signature_version="s3v4", s3={"addressing_style": "path"})
    return boto3.client("s3", region_name=s.aws_region, endpoint_url=endpoint, config=config)


@lru_cache
def s3_client():
    """For server-side calls (head, delete, put)."""
    return _s3(get_settings().aws_endpoint_url)


@lru_cache
def s3_presign_client():
    """For URLs handed to the browser."""
    s = get_settings()
    return _s3(s.s3_presign_endpoint_url or s.aws_endpoint_url)


def reset_clients() -> None:
    dynamodb_table.cache_clear()
    s3_client.cache_clear()
    s3_presign_client.cache_clear()


def create_local_resources() -> None:
    """Create the table and bucket. Used for local development and tests only;
    in AWS these are created by Terraform with identical keys."""
    s = get_settings()
    ddb = boto3.client("dynamodb", **_kwargs())
    existing = ddb.list_tables()["TableNames"]
    if s.table_name not in existing:
        ddb.create_table(
            TableName=s.table_name,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": n, "AttributeType": "S"} for n in ("PK", "SK", "GSI1PK", "GSI1SK")
            ],
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )
    s3 = s3_client()
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    if s.bucket_name not in buckets:
        if s.aws_region == "us-east-1":
            s3.create_bucket(Bucket=s.bucket_name)
        else:
            s3.create_bucket(
                Bucket=s.bucket_name,
                CreateBucketConfiguration={"LocationConstraint": s.aws_region},
            )
        s3.put_bucket_cors(
            Bucket=s.bucket_name,
            CORSConfiguration={
                "CORSRules": [
                    {
                        "AllowedOrigins": [s.app_url],
                        "AllowedMethods": ["GET", "POST", "PUT"],
                        "AllowedHeaders": ["*"],
                        "MaxAgeSeconds": 3000,
                    }
                ]
            },
        )
