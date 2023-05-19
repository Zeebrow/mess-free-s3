import datetime
from dateutil import tz
from textwrap import dedent
import logging
import hmac
from hashlib import sha256

from signer import AWSConfig, AWSCredentials, get_signing_key

"""
    Use these functions to produce the headers required for GETting S3 objects behind
    your auth wall.

    https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_SHARED_CREDENTIALS_FILE
    https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
    https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
"""

# how AWS defines a hash of nothing
# POST requests require a hash of the content
EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
# timestamp format required for the X_AMZ_DATE_TIMESTAMP header
SIGV4_TIMESTAMP = '%Y%m%dT%H%M%SZ'
# all of our requests will be going to the s3 services
AWS_SERVICE = 's3'


logger = logging.getLogger()


def get_s3_hostname(region, aws_service=AWS_SERVICE):
    return f"{aws_service}.{region}.amazonaws.com"


def post_s3_auth_headers(bucket_name, object_key, query_string='', aws_service=AWS_SERVICE):
    """
    https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
    https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
    Notes:
    policy header - For signature calculation this policy is the string you sign.
    string to sign looks the same as with a GET request

    """

    pass


def get_s3_auth_headers(bucket_name, object_key, aws_service=AWS_SERVICE, profile=None, region=None, byte_range='0-') -> dict:
    """"""
    creds = AWSCredentials(profile=profile)
    profile = AWSConfig(profile=profile, region=region)

    region = profile.region
    aws_access_key_id = creds.aws_access_key_id
    aws_secret_access_key = creds.aws_secret_access_key

    x_amz_date_timestamp = datetime.datetime.now(tz=tz.tzutc()).strftime(SIGV4_TIMESTAMP)
    date_yyyymmdd = x_amz_date_timestamp[:8]
    scope = f"{date_yyyymmdd}/{region}/{aws_service}/aws4_request"
    credential = f"{aws_access_key_id}/{scope}"

    signing_key = get_signing_key(aws_secret_access_key, date_yyyymmdd, region, aws_service)

    host_header = get_s3_hostname(region, aws_service)
    range_header = "bytes={}".format(byte_range)
    x_amz_date_header = x_amz_date_timestamp
    x_amz_content_sha256_header = EMPTY_HASH

    # create the canonical request to use in the signature
    # we use 4 headers to calculate the signature because don't touch it it works

    # Instead of seeing a blank line in the canonical request
    query_string = '',
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

    logger.debug("canonical request: {}".format(cr))
    cr_sha256sum = sha256(cr.encode('utf-8')).hexdigest()
    logger.debug("cr_sha256sum={}".format(cr_sha256sum))

    # @@@ POST policy ?
    string_to_sign = dedent(f"""\
    AWS4-HMAC-SHA256
    {x_amz_date_header}
    {date_yyyymmdd}/{region}/{aws_service}/aws4_request
    {cr_sha256sum}""")

    logger.debug("string to sign: {}".format(string_to_sign))

    signature = hmac.new(key=signing_key, msg=string_to_sign.encode('utf-8'), digestmod=sha256).hexdigest()
    logger.debug("signature={}".format(signature))

    return {
        'host': host_header,
        'range': range_header,
        'x-amz-content-sha256': x_amz_content_sha256_header,
        'x-amz-date': x_amz_date_header,
        'Authorization': f"AWS4-HMAC-SHA256 Credential={credential}/{scope},SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature={signature}",
    }


if __name__ == '__main__':
    import argparse
    import requests

    def get_url(region, bucket_name, object_key, aws_service=AWS_SERVICE):
        return f'https://{get_s3_hostname(region, aws_service)}/{bucket_name}/{object_key}'

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

    parser = argparse.ArgumentParser("save an object from s3")
    parser.add_argument("-b", "--bucket-name", reguired=True, action='store', help='Name of a bucket to get a file from')
    parser.add_argument("-k", "--object-key", required=True, action='store', help='Path to a particular file in s3')
    parser.add_argument("-r", "--region", default=None, action='store', help='AWS region in which the bucket resides. If left empty, will be filled using default profile in ~/aws/config.')
    parser.add_argument("-p", "--profile", default=None, action='store', help='Profile to use')

    args = parser.parse_args()
    config = AWSConfig(region=args.region, profile=args.profile)
    creds = AWSCredentials(profile=args.profile, credentials_filepath=args.credentials_filepath)

    obj = get_s3_object(region=args.region, profile=args.profile, bucket_name=args.bucket_name, object_key=args.object_key)
    print(obj)
    filename = args.object_key.split('/')[-1]

    with open(filename, 'w') as f:
        f.write(obj)
