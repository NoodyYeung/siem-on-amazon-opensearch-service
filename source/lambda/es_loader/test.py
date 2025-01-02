
import json
import os
import re
import sys
import time
import urllib.parse
import warnings
from functools import lru_cache, wraps

import boto3
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.metrics import MetricUnit
from opensearchpy import AuthenticationException, AuthorizationException
import configparser
import csv
import importlib
import ipaddress
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import boto3
import botocore
import jmespath
import requests
from aws_lambda_powertools import Logger
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection
import siem
from siem import geodb, ioc, utils, xff
S3_ENDPOINT_DNS = os.environ.get('S3_ENDPOINT_DNS')

logger = Logger(stream=sys.stdout, log_record_order=["level", "message"])

logger.info("boto3 version" + boto3.__version__);

def lambda_handler(event, context):
    geoipbucket = "test897987789"
    csv_filename = "AWSLogs/558454069898/vpcflowlogs/ap-east-1/2023/12/13/558454069898_vpcflowlogs_ap-east-1_fl-05592e06c44882ed0_20231213T0000Z_9ef0c3ac.log.gz"
    s3geo = boto3.resource('s3', 'ap-east-1', config=botocore.config.Config(s3={'addressing_style':'path'}),endponit_url = S3_ENDPOINT_DNS )
    bucket = s3geo.Bucket(geoipbucket)
    logger.info(str(bucket.get_available_subresources()))
    s3obj = csv_filename
    local_file = f'/tmp/a.log.gz'
    downloaded_bytes = 0
    def download_progress(chunk):
        # Define a callback function to log download progress
        downloaded_bytes += len(chunk)
        print(f"Downloaded: {downloaded_bytes} bytes")
    # Create a file 
    with open('/tmp/z.txt', 'w') as f:
        f.write('hello world')
    bucket.upload_file('/tmp/z.txt', 'z.txt')
    logger.info(f'z.txt is uploaded as {local_file}')
    logger.info(f'get {s3obj} from {geoipbucket}')
    bucket.download_file(s3obj, local_file)
    logger.info(f'{s3obj} is downloaded as {local_file}')