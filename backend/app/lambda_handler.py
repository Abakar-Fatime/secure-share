"""AWS Lambda entry point.

HTTP requests from API Gateway are translated to ASGI by Mangum. A direct invocation
with {"ss_cli": "create-admin", "email": ..., "name": ...} creates the first admin;
only someone with IAM permission to invoke the function can do this.
"""

from mangum import Mangum

from .main import app

_http = Mangum(app, lifespan="off")


def handler(event, context):
    if isinstance(event, dict) and event.get("ss_cli") == "create-admin":
        from .cli import create_admin

        return {"invite_url": create_admin(event["email"], event["name"])}
    return _http(event, context)
