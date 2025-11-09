import json
import boto3
import urllib.parse
import logging
from typing import Any
from http import HTTPStatus

DEFAULT_BUCKET = 'mars-project-assets-csaw'
DEFAULT_PREFIX = 'imgs'
PRESIGNED_URL_EXPIRY = 600
CONTENT_TYPE_JSON = 'application/json'

logger = logging.getLogger(__name__)

s3_client = boto3.client('s3')

def handle(event: dict[str, Any], context: Any) -> dict[str, Any]:
    req = event.get('requestContext', {}).get('http', {})
    path = req.get('path', '')
    query_params = event.get('queryStringParameters') or {}

    if path == '/api/view':
        return handle_view(query_params)
    elif path == '/api/list':
        return handle_list(query_params)
    
    return not_found_response()

def handle_view(query_params: dict[str, str]) -> dict[str, Any]:
    key = query_params.get('path')
    bucket = query_params.get('debug_bucket', DEFAULT_BUCKET)
    
    if not key:
        return not_found_response()
    
    presigned_url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=PRESIGNED_URL_EXPIRY
    )
    
    return {
        'statusCode': HTTPStatus.FOUND,
        'headers': {
            'Location': presigned_url,
        },
        'body': ''
    }
        
def handle_list(query_params: dict[str, str]) -> dict[str, Any]:
    prefix = query_params.get('path', DEFAULT_PREFIX)
    bucket = query_params.get('debug_bucket', DEFAULT_BUCKET)
    
    paginator = s3_client.get_paginator('list_objects_v2')
    objects = []

    try:
        for page in paginator.paginate(
            Bucket=bucket,
            Prefix=prefix,
            MaxKeys=1000,
        ):
            for obj in page.get('Contents', []):
                objects.append(obj['Key'])
    except Exception as e:
        logger.error(e)
        return not_found_response()

    return {
        'statusCode': HTTPStatus.OK,
        'headers': {
            'Content-Type': CONTENT_TYPE_JSON,
        },
        'body': json.dumps(objects)
    }

def not_found_response():
    return {
        'statusCode': HTTPStatus.NOT_FOUND,
        'body': ''
    }
