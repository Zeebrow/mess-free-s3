import hmac
import os
import sys
from configparser import ConfigParser
import logging
from hashlib import sha256


logger = logging.getLogger(__name__)

EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
SIGV4_TIMESTAMP = '%Y%m%dT%H%M%SZ'
AWS_SERVICE = 's3'
REGIONS = [
    "af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
    "ca-central-1", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "me-central-1", "me-south-1", "sa-east-1",
    "us-east-1", "us-east-2", "us-gov-east-1", "us-gov-west-1", "us-west-1", "us-west-2",
]  # not all, but a good start...


class AWSCredentials:
    """
    Retrieves your AWS credentials in the following manner:

    1. hardcoded: Explicitly initializing the AWSCredentials object with values for
    `aws_access_key_id` and `aws_secret_access_key`.
    1. environment: variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` override
    values retrieved from the shared credentials file (whether or not they exist).
    1. shared credentials file: If either `aws_access_key_id` or `aws_secret_access_key`
    are not set according to the above, values from the shared credentials file replace
    the value for the one that exists, and set a value for the one that does not. The
    shared credentials file's default location is `$HOME/.aws/credentials`, and may be
    overriden by hardcoding `credentials_filepath` or setting the `AWS_SHARED_CREDENTIALS_FILE`
    environment variable (hardcoding takes precedence). If `profile` is not set with
    a hardcoded value or with the `AWS_PROFILE` environment variable, the credentials
    under the `[default]` heading will be used.

    """
    def __init__(self, profile=None, credentials_filepath=None, aws_access_key_id=None, aws_secret_access_key=None) -> None:
        self.credentials_filepath = self._get_cred_filepath(credentials_filepath)
        self.profile = self._get_profile(profile)  # against the better advice of aws...
        self.aws_access_key_id = self._get_aws_access_key_id(aws_access_key_id)
        self.aws_secret_access_key = self._get_aws_secret_access_key(aws_secret_access_key)

    def __repr__(self):
        return "{0}(profile='{1}', aws_access_key_id='{2}', aws_secret_access_key='{3}')".format(
            type(self).__name__,
            self.profile,
            self.aws_access_key_id[:4] + '*' * (len(self.aws_access_key_id) - 4),
            '*' * len(self.aws_secret_access_key)
        )

    def _get_cred_filepath(self, credentials_filepath=None) -> str:
        """
        returns absolute filepath to a shared aws credentials file, or raises
        FileNotFound if neither credentials_filepath nor environment variable
        AWS_SHARED_CREDENTIALS_FILE is provided, the default is returned (/home/user/.aws/credentials on Linux)

        precedence is hardcoded -> AWS_SHARED_CREDENTIALS_FILE -> platform default
        """
        # https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_SHARED_CREDENTIALS_FILE
        if credentials_filepath is not None:
            if not os.path.exists(credentials_filepath):
                # @Bug: should not raise if credentials are already set - but needs
                # to be called before credentials are set!!
                raise FileNotFoundError("No credentials file exists at {}".format(credentials_filepath))
            return credentials_filepath

        if sys.platform == 'linux':
            credentials_filepath = os.environ.get(
                "AWS_SHARED_CREDENTIALS_FILE",
                os.path.join(os.path.expanduser("~"), ".aws", "credentials")
            )

            if not os.path.exists(credentials_filepath):
                raise FileNotFoundError("No credentials file exists at {}".format(credentials_filepath))
        else:
            raise NotImplementedError("'{}' is not a supported platform".format(sys.platform))

        return credentials_filepath

    def _get_profile(self, profile=None):
        """
        returns the name of a profile or 'default'
        assumes that a config file exists at self.config_filepath and is a valid .ini file
        order of presedence is hardcoded -> AWS_PROFILE environment variable -> 'default'
        """
        if profile:
            return profile
        return os.environ.get("AWS_PROFILE", 'default')

    def _get_aws_access_key_id(self, aws_access_key_id=None):
        """
        returns a value for the aws_access_key_id

        order of precedence: hardcoded -> AWS_ACCESS_KEY_ID environment variable -> aws_access_key_id credentials file key
        """
        if aws_access_key_id is not None:
            return aws_access_key_id
        parser = ConfigParser()
        parser.read(self.credentials_filepath)
        # raises here if no default profile
        creds_access_key_id = parser[self.profile].get("aws_access_key_id", None)
        aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID", creds_access_key_id)
        return aws_access_key_id

    def _get_aws_secret_access_key(self, aws_secret_access_key=None):
        """
        returns a value for the aws_secret_access_key

        order of precedence: hardcoded -> AWS_SECRET_ACCESS_KEY environment variable -> aws_secret_access_key credentials file key
        """
        if aws_secret_access_key is not None:
            return aws_secret_access_key
        parser = ConfigParser()
        parser.read(self.credentials_filepath)
        creds_secret_access_key = parser[self.profile].get("aws_secret_access_key", None)
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY", creds_secret_access_key)
        return aws_secret_access_key


class AWSConfig:
    def __init__(self, region: str = None, profile: str = None, config_filepath: str = None):
        self.config_filepath = self._get_config_filepath(config_filepath)
        self.profile = self._get_profile(profile)
        self.region = self._get_region(region)
        # unsused, even though technically a common key in an an aws config
        # self.output = None

    def _get_config_filepath(self, config_filepath=None) -> str:
        """
        returns the absolute path to a a file, or raises
        order of presedence is hardcoded -> AWS_CONFIG_FILE -> $HOME/.aws/config on Linux, %UserProfile%\\.aws\\config on Windows

        https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_CONFIG_FILE
        """
        if config_filepath is None:
            if sys.platform == 'linux':
                config_filepath = os.environ.get(
                    "AWS_CONFIG_FILE",
                    os.path.join(os.path.expanduser("~"), ".aws", "config")
                )
                if not os.path.exists(config_filepath):
                    raise FileNotFoundError("No file found at '{}'".format(config_filepath))
                return config_filepath
            else:
                raise NotImplementedError("'{}' is not a supported platform".format(sys.platform))
        else:
            if not os.path.exists(config_filepath):
                raise FileNotFoundError("No file found at '{}'".format(config_filepath))
            return config_filepath

    def _get_profile(self, profile=None):
        """
        returns the name of a profile or 'default'
        assumes that a config file exists at self.config_filepath and is a valid .inri file
        order of presedence is hardcoded -> AWS_PROFILE environment variable -> 'default'
        """
        if profile:
            return profile
        return os.environ.get("AWS_PROFILE", 'default')

    def _get_region(self, region=None):
        """
        returns the name of an aws region, or raises ValueError if the region cannot be determined.
        order of presedence is hardcoded -> AWS_DEFAULT_REGION environment variable -> aws config file
        """
        if region is not None:
            return region

        parser = ConfigParser()
        parser.read(self.config_filepath)
        if self.profile == 'default':
            config_file_region = parser[self.profile].get('region', None)
        else:
            config_file_region = parser[f"profile {self.profile}"].get('region', None)
        region = os.getenv("AWS_DEFAULT_REGION", config_file_region)

        if region is None:
            raise ValueError("region unset and cannot be None")
        if region not in REGIONS:
            logger.warning("Specified region '{}' might not be valid".format(region))

        return region


def get_signing_key(secret_access_key, datestring, region, service):
    """
    Generate a signing key
    """
    a = hmac.new(key=f'AWS4{secret_access_key}'.encode(), msg=datestring.encode('utf-8'), digestmod=sha256).digest()
    b = hmac.new(key=a, msg=region.encode('utf-8'), digestmod=sha256).digest()
    c = hmac.new(key=b, msg=service.encode('utf-8'), digestmod=sha256).digest()
    d = hmac.new(key=c, msg='aws4_request'.encode('utf-8'), digestmod=sha256).digest()
    return d
