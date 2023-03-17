import requests
import datetime
from dateutil import tz
from textwrap import dedent
import logging
import hmac
from hashlib import sha256

from signer import AWSConfig, AWSCredentials, get_signing_key


EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
SIGV4_TIMESTAMP = '%Y%m%dT%H%M%SZ'
AWS_SERVICE = 's3'
logger = logging.getLogger()


def get_hostname(region, aws_service=AWS_SERVICE):
    return f"{aws_service}.{region}.amazonaws.com"


def get_s3_auth_headers(bucket_name, object_key, query_string='', aws_service=AWS_SERVICE, profile=None, region=None):
    creds = AWSCredentials(profile=profile)
    profile = AWSConfig(profile=profile, region=region)

    region = profile.region
    aws_access_key_id = creds.aws_access_key_id
    aws_secret_access_key = creds.aws_secret_access_key

    x_amz_date_timestamp = datetime.datetime.now(tz=tz.tzutc()).strftime(SIGV4_TIMESTAMP)
    date_yyyymmdd = x_amz_date_timestamp[:8]
    scope = f"{date_yyyymmdd}/{region}/{aws_service}/aws4_request"

    signing_key = get_signing_key(aws_secret_access_key, date_yyyymmdd, region, aws_service)

    host_header = get_hostname(region, aws_service)
    range_header = 'bytes=0-'
    x_amz_date_header = x_amz_date_timestamp
    x_amz_content_sha256_header = EMPTY_HASH

    # create the canonical request to use in the signature
    # we use 4 headers to calculate the signature because don't touch it it works
    cr = dedent(f"""\
    GET
    /{bucket_name}/{object_key}
    {query_string}
    host:{host_header}
    range:{range_header}
    x-amz-content-sha256:{x_amz_content_sha256_header}
    x-amz-date:{x_amz_date_header}

    host;range;x-amz-content-sha256;x-amz-date
    {x_amz_content_sha256_header}""")

    print(cr)
    logger.debug("canonical request: {}".format(cr))
    cr_sha256sum = sha256(cr.encode('utf-8')).hexdigest()
    print(cr_sha256sum)
    logger.debug("cr_sha256sum={}".format(cr_sha256sum))

    string_to_sign = dedent(f"""\
    AWS4-HMAC-SHA256
    {x_amz_date_header}
    {date_yyyymmdd}/{region}/{aws_service}/aws4_request
    {cr_sha256sum}""")

    print(string_to_sign)
    logger.debug("string to sign: {}".format(string_to_sign))

    signature = hmac.new(key=signing_key, msg=string_to_sign.encode('utf-8'), digestmod=sha256).hexdigest()
    print(signature)
    logger.debug("signature={}".format(signature))

    ###############################################################################
    # build GET request headers
    ###############################################################################
    return {
        'host': host_header,
        'range': range_header,
        'x-amz-content-sha256': x_amz_content_sha256_header,
        'x-amz-date': x_amz_date_header,
        'Authorization': f"AWS4-HMAC-SHA256 Credential={aws_access_key_id}/{scope},SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature={signature}",
    }


if __name__ == '__main__':
    import argparse

    def get_url(region, bucket_name, object_key, aws_service=AWS_SERVICE):
        return f'https://{get_hostname(region, aws_service)}/{bucket_name}/{object_key}'

    def get_s3_object(profile, region, bucket_name, object_key):
        """
        example using requests
        """
        r = requests.Request(method='GET', url=get_url(region, bucket_name, object_key))
        r.headers = get_s3_auth_headers(region=region, profile=profile, bucket_name=bucket_name, object_key=object_key)
        s = requests.Session()
        response = s.send(s.prepare_request(r))
        logger.debug("status={}".format(response.status_code))
        return response.text

    region = 'us-east-1'
    bucket_name = 'bs-bucket-asdfasdf2'
    object_key = 'extra-page.html'

    parser = argparse.ArgumentParser("save an object from s3")
    parser.add_argument("-b", "--bucket-name", default=bucket_name, action='store', help='Name of a bucket to get a file from')
    parser.add_argument("-k", "--object-key", default=object_key, action='store', help='Path to a particular file in s3')
    parser.add_argument("-r", "--region", default=region, action='store', help='AWS region in which the bucket resides. If left empty, will be filled using default profile in ~/aws/config.')
    parser.add_argument("-p", "--profile", default='default', action='store', help='Profile to use')

    args = parser.parse_args()


    obj = get_s3_object(region=args.region, profile=args.profile, bucket_name=args.bucket_name, object_key=args.object_key)
    print(obj)
    filename = object_key.split('/')[-1]

    with open(filename, 'w') as f:
        f.write(obj)
