from hashlib import sha256
import hmac
from textwrap import dedent
import pytest
import tempfile
import os
import sys
from pathlib import Path
import shutil
import warnings

from s3_requests.signer import get_signing_key, AWSConfig, AWSCredentials


@pytest.fixture
def aws_credentials():
    _, credentials_file = tempfile.mkstemp()
    contents = dedent("""\
        [default]
        aws_access_key_id = AKIA1234567890ABCDEF
        aws_secret_access_key = BASE64STRING+/length40abcdefghijklmnopqr
        [profile1]
        aws_access_key_id = AKIA1234567890ABCDED
        aws_secret_access_key = BASE64STRING+/length40abcdefghijklmnopqp
    """)
    with open(credentials_file, 'w') as f:
        f.write(contents)
    yield credentials_file
    os.unlink(credentials_file)


@pytest.fixture
def bad_aws_credentials():
    _, credentials_file = tempfile.mkstemp()
    contents = dedent("""\
        [profile1]
        aws_access_key_id = AKIA1234567890ABCDED
        aws_secret_access_key = BASE64STRING+/length40abcdefghijklmnopqp
    """)
    with open(credentials_file, 'w') as f:
        f.write(contents)
    yield credentials_file
    os.unlink(credentials_file)


@pytest.fixture
def aws_config():
    _, config_file = tempfile.mkstemp()
    contents = dedent("""\
        [default]
        region = us-east-1
        output = json
        [profile profile1]
        region = cn-northwest-1
        output = text
    """)
    with open(config_file, 'w') as f:
        f.write(contents)
    yield config_file
    os.unlink(config_file)


@pytest.fixture
def bad_aws_config():
    _, config_file = tempfile.mkstemp()
    contents = dedent("""\
        [profile profile1]
        region = cn-northwest-1
        output = text
        [profile regionless-profile]
        output = text
    """)
    with open(config_file, 'w') as f:
        f.write(contents)
    yield config_file
    os.unlink(config_file)


@pytest.fixture
def aws_config_with_dir(monkeypatch):
    """
    Returns the absolute filepath to a valid AWS config file.
    Sets the HOME environment variable to a temp dir.
    """
    user_home = Path(tempfile.mkdtemp())
    aws_dir = user_home / ".aws"
    aws_dir.mkdir()
    config_file = Path(aws_dir / "config")
    config_file.touch()

    contents = dedent("""\
        [default]
        region = us-east-1
        output = json
        [profile profile1]
        region = cn-northwest-1
        output = text
    """)
    with config_file.open('w') as f:
        f.write(contents)

    with monkeypatch.context() as m:
        if sys.platform in ['linux', 'darwin']:
            m.setenv("HOME", str(user_home.absolute()))
        elif sys.platform == 'win32':
            m.setenv("UserProfile", str(user_home.absolute()))  # should be fine™
        yield config_file

    shutil.rmtree(user_home)


def test_fixtures_work(aws_credentials, aws_config, aws_config_with_dir):
    assert aws_config
    assert aws_credentials
    assert aws_config_with_dir


##############################################################################
# aws config
##############################################################################
################
# filepath
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_CONFIG_FILE
################
def test_aws_config_filepath_os_dependencies(aws_config_with_dir):
    assert AWSConfig(config_filepath=aws_config_with_dir)
    if sys.platform in ['linux', 'darwin']:
        config = AWSConfig(config_filepath=None)
        assert config.config_filepath == os.path.join(os.path.expanduser("~"), ".aws", "config")
    elif sys.platform == 'win32':
        with pytest.raises(NotImplementedError):
            config = AWSConfig(config_filepath=None)
    else:
        warnings.warn("Possibly unsupported platform '{}'".format(sys.platform))


def test_aws_config_filepath_hardcode_overrides_default(aws_config, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("HOME", "/path/to/nowhere")
        assert AWSConfig(config_filepath=aws_config)


def test_aws_config_filepath_hardcode_overrides_environ(aws_config, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_CONFIG_FILE", "/path/to/nowhere")
        assert AWSConfig(config_filepath=aws_config)


def test_aws_config_filepath_environ_overrides_default(aws_config, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_CONFIG_FILE", aws_config)
        assert AWSConfig()


def test_aws_config_raises_filenotfound_default(monkeypatch):
    with pytest.raises(FileNotFoundError):
        with monkeypatch.context() as m:
            # TIL: os.path.expanduser("~") relies on the HOME environment variable (linux)
            m.setenv("HOME", "/path/to/nowhere")
            AWSConfig()


def test_aws_config_raises_filenotfound_hardcoded():
    with pytest.raises(FileNotFoundError):
        AWSConfig(config_filepath='/path/to/nowhere')


####################
# profile
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_PROFILE
####################
def test_aws_config_profile_default(aws_config):
    config = AWSConfig(config_filepath=aws_config)
    assert config.profile == 'default'
    assert config.region == 'us-east-1'


def test_aws_config_profile_hardcode_overrides_default(aws_config):
    config = AWSConfig(config_filepath=aws_config, profile='profile1')
    assert config.profile == 'profile1'
    assert config.region == 'cn-northwest-1'


def test_aws_config_profile_environ_overrides_default(aws_config, monkeypatch: pytest.MonkeyPatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_PROFILE", "profile1")
        config = AWSConfig(config_filepath=aws_config)
        assert config.profile == 'profile1'
        assert config.region == 'cn-northwest-1'


def test_aws_config_profile_hardcode_overrides_environ(aws_config, monkeypatch: pytest.MonkeyPatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_PROFILE", "profile1")
        config = AWSConfig(config_filepath=aws_config, profile='default')
        assert config.profile == 'default'
        assert config.region == 'us-east-1'


def test_aws_config_non_existant_default_profile_raises(bad_aws_config):
    with pytest.raises(KeyError):
        AWSConfig(config_filepath=bad_aws_config)


def test_aws_config_non_existant_hc_profile_raises(aws_config):
    with pytest.raises(KeyError):
        AWSConfig(config_filepath=aws_config, profile='some-profile')


def test_aws_config_non_existant_environ_profile_raises(aws_config, monkeypatch):
    with pytest.raises(KeyError):
        monkeypatch.setenv("AWS_PROFILE", 'non-existant')
        AWSConfig(config_filepath=aws_config)


####################
# #region
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_DEFAULT_REGION
####################
def test_aws_config_region_default(aws_config):
    config = AWSConfig(config_filepath=aws_config)
    assert config.region == 'us-east-1'


def test_aws_config_region_hardcode_overrides_default(aws_config):
    config = AWSConfig(config_filepath=aws_config, region='some-region-1')
    assert config.profile == 'default'
    assert config.region == 'some-region-1'


def test_aws_config_region_environ_overrides_default(aws_config, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_DEFAULT_REGION", "some-region-2")
        config = AWSConfig(config_filepath=aws_config)
        assert config.profile == 'default'
        assert config.region == 'some-region-2'


def test_aws_config_region_hardcode_overrides_environ(aws_config, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_DEFAULT_REGION", "some-region-2")
        config = AWSConfig(config_filepath=aws_config, region='some-region-1')
        assert config.profile == 'default'
        assert config.region == 'some-region-1'


##############################################################################
# credentials
##############################################################################
def test_get_aws_credentials_sets_default_credentials(aws_credentials):
    credentials = AWSCredentials(credentials_filepath=aws_credentials)
    assert credentials.profile == 'default'
    assert credentials.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqr'
    assert credentials.aws_access_key_id == 'AKIA1234567890ABCDEF'


def test_get_aws_credentials_sets_profile_credentials(aws_credentials):
    credentials = AWSCredentials(credentials_filepath=aws_credentials, profile='profile1')
    assert credentials.profile == 'profile1'
    assert credentials.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqp'
    assert credentials.aws_access_key_id == 'AKIA1234567890ABCDED'


def test_credentials_repr_hides_password(aws_credentials):
    creds = AWSCredentials(credentials_filepath=aws_credentials)
    assert "aws_secret_access_key='****************************************'" in creds.__repr__()
    assert "aws_access_key_id='AKIA****************'" in creds.__repr__()


################
# filepath
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_SHARED_CREDENTIALS_FILE
################
def test_aws_creds_filepath_hardcode_overrides_default(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("HOME", "/path/to/nowhere")
        assert AWSCredentials(credentials_filepath=aws_credentials)


def test_aws_creds_filepath_hardcode_overrides_environ(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_SHARED_CREDENTIALS_FILE", "/path/to/nowhere")
        assert AWSCredentials(credentials_filepath=aws_credentials)


def test_aws_creds_filepath_environ_overrides_default(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_SHARED_CREDENTIALS_FILE", aws_credentials)
        assert AWSCredentials()


def test_aws_creds_raises_filenotfound_default(monkeypatch):
    with pytest.raises(FileNotFoundError):
        with monkeypatch.context() as m:
            # m.setenv("UserProfile", "/path/to/nowhere")
            m.setenv("HOME", "/path/to/nowhere")
            AWSCredentials()


####################
# profile
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_PROFILE
####################
def test_aws_creds_profile_raises_when_no_default(bad_aws_credentials):
    """note this might already be tested"""
    with pytest.raises(KeyError):
        AWSCredentials(credentials_filepath=bad_aws_credentials)


def test_aws_creds_profile_doesnt_care_if_no_such_file_when_creds_are_set():
    """this is bad behavior"""
    creds = AWSCredentials(
        aws_access_key_id='AKIA1234567890ABCDEF',
        aws_secret_access_key='BASE64STRING+/length40abcdefghijklmnopqr',
        credentials_filepath='does_not_exist',
    )
    assert creds.aws_access_key_id == 'AKIA1234567890ABCDEF'
    assert creds.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqr'


def test_aws_creds_profile_doesnt_care_if_bad_profile_when_creds_are_set(aws_credentials):
    """note this might already be tested"""
    creds = AWSCredentials(
        aws_access_key_id='AKIA1234567890ABCDEF',
        aws_secret_access_key='BASE64STRING+/length40abcdefghijklmnopqr',
        credentials_filepath=aws_credentials,
        profile='does_not_exist'
    )
    assert creds.aws_access_key_id == 'AKIA1234567890ABCDEF'
    assert creds.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqr'


def test_aws_creds_profile_default(aws_credentials):
    creds = AWSCredentials(credentials_filepath=aws_credentials)
    assert creds.profile == 'default'
    assert creds.aws_access_key_id == 'AKIA1234567890ABCDEF'
    assert creds.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqr'


def test_aws_creds_profile_hardcode_overrides_default(aws_credentials):
    creds = AWSCredentials(credentials_filepath=aws_credentials, profile='profile1')
    assert creds.profile == 'profile1'
    assert creds.aws_access_key_id == 'AKIA1234567890ABCDED'
    assert creds.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqp'


def test_aws_creds_profile_environ_overrides_default(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_PROFILE", "profile1")
        creds = AWSCredentials(credentials_filepath=aws_credentials)
        assert creds.profile == 'profile1'
        assert creds.aws_access_key_id == 'AKIA1234567890ABCDED'
        assert creds.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqp'


def test_aws_creds_profile_hardcode_overrides_environ(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_PROFILE", "profile1")
        creds = AWSCredentials(credentials_filepath=aws_credentials, profile='default')
        assert creds.profile == 'default'
        assert creds.aws_access_key_id == 'AKIA1234567890ABCDEF'
        assert creds.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqr'


####################
# aws_access_key_id
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_ACCESS_KEY_ID
####################
def test_aws_creds_key_id_default(aws_credentials):
    creds = AWSCredentials(credentials_filepath=aws_credentials)
    assert creds.aws_access_key_id == 'AKIA1234567890ABCDEF'


def test_aws_creds_key_id_hardcode_overrides_default(aws_credentials):
    creds = AWSCredentials(credentials_filepath=aws_credentials, aws_access_key_id='AKIA789')
    assert creds.aws_access_key_id == 'AKIA789'


def test_aws_creds_key_id_environ_overrides_default(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_ACCESS_KEY_ID", "AKIA123")
        creds = AWSCredentials(credentials_filepath=aws_credentials)
        assert creds.aws_access_key_id == 'AKIA123'


def test_aws_creds_key_id_hardcode_overrides_environment(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_ACCESS_KEY_ID", "AKIA123")
        creds = AWSCredentials(credentials_filepath=aws_credentials, aws_access_key_id='hc_AKIA123')
        assert creds.aws_access_key_id == 'hc_AKIA123'


####################
# aws_secret_access_key
# https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list-AWS_SECRET_ACCESS_KEY
####################
def test_aws_creds_secret_default(aws_credentials):
    creds = AWSCredentials(credentials_filepath=aws_credentials)
    assert creds.aws_secret_access_key == 'BASE64STRING+/length40abcdefghijklmnopqr'


def test_aws_creds_secret_hardcode_overrides_default(aws_credentials):
    creds = AWSCredentials(credentials_filepath=aws_credentials, aws_secret_access_key='hc_secret123')
    assert creds.aws_secret_access_key == 'hc_secret123'


def test_aws_creds_secret_environ_overrides_default(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_SECRET_ACCESS_KEY", "Secret123")
        creds = AWSCredentials(credentials_filepath=aws_credentials)
        assert creds.aws_secret_access_key == 'Secret123'


def test_aws_creds_secret_hardcode_overrides_environment(aws_credentials, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("AWS_SECRET_ACCESS_KEY", "Secret123")
        creds = AWSCredentials(credentials_filepath=aws_credentials, aws_secret_access_key='hc_secret_123')
        assert creds.aws_secret_access_key == 'hc_secret_123'


def test_aws_config_region_unset_raises(bad_aws_config):
    with pytest.raises(ValueError):
        AWSConfig(config_filepath=bad_aws_config, profile='regionless-profile')


##############################################################################
# signature
# https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#example-signature-calculations
##############################################################################
def test_signing_key_produces_correct_signature():
    EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # noqa: F841
    aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'  # noqa: F841
    aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    request_timestamp = '20130524T000000Z'
    bucket_name = 'examplebucket'  # noqa: F841
    region = 'us-east-1'
    service = 's3'
    url = 'https://examplebucket.s3.amazonaws.com/photos/photo1.jpg'  # noqa: F841

    signing_key = get_signing_key(aws_secret_access_key, datestring=request_timestamp[:8], region=region, service=service)

    cr = dedent("""\
    GET
    /test.txt

    host:examplebucket.s3.amazonaws.com
    range:bytes=0-9
    x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    x-amz-date:20130524T000000Z

    host;range;x-amz-content-sha256;x-amz-date
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""")

    hex_cr = sha256(cr.encode('utf-8')).hexdigest()
    assert hex_cr == '7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972'

    string_to_sign = dedent(f"""\
    AWS4-HMAC-SHA256
    20130524T000000Z
    20130524/us-east-1/s3/aws4_request
    {hex_cr}""")
    signature = hmac.new(key=signing_key, msg=string_to_sign.encode('utf-8'), digestmod=sha256).hexdigest()
    assert signature == 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'
