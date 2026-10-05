import json

import boto3
import pytest
from moto import mock_aws

from tests.loader import load_lambda

response = load_lambda("response")

ACC_BUCKET = "adl-patients-111122223333"
BASELINE = json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "Base", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                                                              "Resource": f"arn:aws:s3:::{ACC_BUCKET}/*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-north-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.delenv("DRY_RUN", raising=False)


@mock_aws
def test_disable_key_dry_run_by_default():
    iam = boto3.client("iam")
    iam.create_user(UserName="dev-adl")
    key = iam.create_access_key(UserName="dev-adl")["AccessKey"]["AccessKeyId"]
    out = response.handler({"actions": ["disable_access_key"], "context": {"user_name": "dev-adl", "access_key_id": key}})
    assert out["results"][0]["status"] == "would_disable"
    assert iam.list_access_keys(UserName="dev-adl")["AccessKeyMetadata"][0]["Status"] == "Active"


@mock_aws
def test_disable_key_live(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    iam = boto3.client("iam")
    iam.create_user(UserName="dev-adl")
    key = iam.create_access_key(UserName="dev-adl")["AccessKey"]["AccessKeyId"]
    out = response.handler({"actions": ["disable_access_key"], "context": {"user_name": "dev-adl", "access_key_id": key}})
    assert out["results"][0]["status"] == "disabled"
    assert iam.list_access_keys(UserName="dev-adl")["AccessKeyMetadata"][0]["Status"] == "Inactive"


def test_disable_key_without_user_is_skipped():
    out = response.handler({"actions": ["disable_access_key"], "context": {}})
    assert out["results"][0]["status"] == "skipped"


def _ec2_setup():
    ec2 = boto3.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
    app = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc)["GroupId"]
    iso = ec2.create_security_group(GroupName="iso", Description="iso", VpcId=vpc)["GroupId"]
    inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[app])["Instances"][0]["InstanceId"]
    return ec2, inst, app, iso


@mock_aws
def test_isolate_instance_live(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "false")
    ec2, inst, app, iso = _ec2_setup()
    monkeypatch.setenv("ISOLATION_SG", iso)
    out = response.handler({"actions": ["isolate_instance"], "context": {"instance_id": inst}})["results"][0]
    assert out["status"] == "isolated" and out["snapshots"]
    desc = ec2.describe_instances(InstanceIds=[inst])["Reservations"][0]["Instances"][0]
    assert [g["GroupId"] for g in desc["SecurityGroups"]] == [iso]
    assert {"Key": "quarantine", "Value": "true"} in desc["Tags"]


@mock_aws
def test_isolate_instance_dry_run_changes_nothing(monkeypatch):
    ec2, inst, app, iso = _ec2_setup()
    monkeypatch.setenv("ISOLATION_SG", iso)
    out = response.handler({"actions": ["isolate_instance"], "context": {"instance_id": inst}})["results"][0]
    assert out["status"] == "would_isolate" and out["previous_groups"] == [app]
    desc = ec2.describe_instances(InstanceIds=[inst])["Reservations"][0]["Instances"][0]
    assert [g["GroupId"] for g in desc["SecurityGroups"]] == [app]
    assert ec2.describe_snapshots(Filters=[{"Name": "tag:quarantine", "Values": ["true"]}])["Snapshots"] == []


@mock_aws
def test_restore_bucket_policy(monkeypatch):
    monkeypatch.setenv("PATIENTS_BUCKET", ACC_BUCKET)
    monkeypatch.setenv("BASELINE_POLICY_PARAM", "/adl/baseline-bucket-policy")
    boto3.client("s3", region_name="eu-north-1").create_bucket(Bucket=ACC_BUCKET, CreateBucketConfiguration={"LocationConstraint": "eu-north-1"})
    boto3.client("ssm").put_parameter(Name="/adl/baseline-bucket-policy", Value=BASELINE, Type="String")
    s3 = boto3.client("s3", region_name="eu-north-1")
    s3.put_bucket_policy(Bucket=ACC_BUCKET, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "Backdoor", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{ACC_BUCKET}/*"}]}))
    ctx = {"bucket": ACC_BUCKET}
    assert response.handler({"actions": ["restore_bucket_policy"], "context": ctx})["results"][0]["status"] == "would_restore"
    assert "Backdoor" in s3.get_bucket_policy(Bucket=ACC_BUCKET)["Policy"]
    monkeypatch.setenv("DRY_RUN", "false")
    assert response.handler({"actions": ["restore_bucket_policy"], "context": ctx})["results"][0]["status"] == "restored"
    assert "Backdoor" not in s3.get_bucket_policy(Bucket=ACC_BUCKET)["Policy"]


def test_restore_refuses_other_buckets(monkeypatch):
    monkeypatch.setenv("PATIENTS_BUCKET", ACC_BUCKET)
    monkeypatch.setenv("BASELINE_POLICY_PARAM", "/adl/x")
    out = response.handler({"actions": ["restore_bucket_policy"], "context": {"bucket": "autre-bucket"}})["results"][0]
    assert out["status"] == "skipped"


def test_unknown_action_and_errors_do_not_block():
    out = response.handler({"actions": ["nope", "disable_access_key"], "context": {}})["results"]
    assert [r["status"] for r in out] == ["unknown", "skipped"]
