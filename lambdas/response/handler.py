"""Lambda "réponse" : actions de confinement, en DRY-RUN par défaut.

Chaque action est indépendante et n'a, côté IAM, que le droit qui lui correspond.
Avec DRY_RUN != "false", seules des lectures sont faites et le résultat décrit ce qui
aurait été modifié.

Variables d'environnement : DRY_RUN, ISOLATION_SG, PATIENTS_BUCKET, BASELINE_POLICY_PARAM
"""
import json
import logging
import os

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)


def client(name):
    return boto3.client(name)


def dry_run():
    return os.environ.get("DRY_RUN", "true").lower() != "false"


def disable_access_key(ctx):
    user, key = ctx.get("user_name"), ctx.get("access_key_id")
    if not user or not key:
        return {"action": "disable_access_key", "status": "skipped", "reason": "pas de clé IAM d'utilisateur dans le contexte"}
    result = {"action": "disable_access_key", "user": user, "access_key_id": key, "dry_run": dry_run()}
    if not dry_run():
        client("iam").update_access_key(UserName=user, AccessKeyId=key, Status="Inactive")
    result["status"] = "would_disable" if dry_run() else "disabled"
    return result


def isolate_instance(ctx):
    instance_id, sg = ctx.get("instance_id"), os.environ.get("ISOLATION_SG")
    if not instance_id or not sg:
        return {"action": "isolate_instance", "status": "skipped", "reason": "instance ou groupe d'isolement inconnu"}
    ec2 = client("ec2")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    volumes = [m["Ebs"]["VolumeId"] for m in inst.get("BlockDeviceMappings", []) if "Ebs" in m]
    result = {"action": "isolate_instance", "instance_id": instance_id, "volumes": volumes,
              "previous_groups": [g["GroupId"] for g in inst.get("SecurityGroups", [])], "dry_run": dry_run()}
    if not dry_run():
        # Preuve d'abord (snapshot), puis coupure réseau, puis marquage
        snaps = [ec2.create_snapshot(VolumeId=v, Description=f"quarantine {instance_id}",
                                     TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "quarantine", "Value": "true"}]}]
                                     )["SnapshotId"] for v in volumes]
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[sg])
        ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "quarantine", "Value": "true"}])
        result["snapshots"] = snaps
    result["status"] = "would_isolate" if dry_run() else "isolated"
    return result


def restore_bucket_policy(ctx):
    bucket, expected = ctx.get("bucket"), os.environ.get("PATIENTS_BUCKET")
    param = os.environ.get("BASELINE_POLICY_PARAM")
    if not bucket or bucket != expected or not param:
        return {"action": "restore_bucket_policy", "status": "skipped",
                "reason": "bucket hors périmètre ou politique de référence absente"}
    result = {"action": "restore_bucket_policy", "bucket": bucket, "dry_run": dry_run()}
    baseline = client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    json.loads(baseline)  # refuse une référence corrompue avant d'écrire quoi que ce soit
    if not dry_run():
        client("s3").put_bucket_policy(Bucket=bucket, Policy=baseline)
    result["status"] = "would_restore" if dry_run() else "restored"
    return result


ACTIONS = {"disable_access_key": disable_access_key, "isolate_instance": isolate_instance,
           "restore_bucket_policy": restore_bucket_policy}


def handler(event, _ctx=None):
    results = []
    for name in event.get("actions", []):
        fn = ACTIONS.get(name)
        if fn is None:
            results.append({"action": name, "status": "unknown"})
            continue
        try:
            results.append(fn(event.get("context", {})))
        except Exception as exc:  # une action en échec ne bloque pas les suivantes
            log.exception("action %s en échec", name)
            results.append({"action": name, "status": "error", "error": str(exc)})
    log.info(json.dumps({"rule_id": event.get("rule_id"), "results": results}))
    return {"rule_id": event.get("rule_id"), "results": results}
