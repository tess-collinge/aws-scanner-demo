#!/usr/bin/env python3
"""
EC2 Misconfiguration Detection System

Scans an AWS account for common EC2 security misconfigurations and reports findings with severity, description, and remediation.

Usage:
  python ec2_misconfig_scanner.py [--region REGION] [--profile PROFILE]
"""

"""todo: further field support for output, like resource tags, account ID, region, etc. - would be useful for SIEM ingestion and triage. MITRE?"""
""""""
import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

@dataclass
class Finding:
    """This is what one of the security findings looks like, can be expanded with further fields"""
    title: str
    severity: str
    resource_id: str
    resource_type: str
    description: str
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "description": self.description,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)


def get_boto_session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        logger.info("Authenticated as: %s", identity.get("Arn"))
        logger.info("Account: %s", identity.get("Account"))
        logger.info("Region: %s", session.region_name or "default")
        return session
    except NoCredentialsError:
        logger.error(
            "No AWS credentials found. Run 'aws configure' or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY."
        )
        sys.exit(1)
    except ClientError as e:
        logger.error("AWS authentication failed: %s", e)
        sys.exit(1)
    except EndpointConnectionError as e:
        logger.error("Could not connect to AWS endpoint: %s", e)
        sys.exit(1)


def paginate(client: Any, method: str, key: str, **kwargs: Any) -> Iterable[Dict[str, Any]]:
    """Generic paginator helper. Yields items from the specified key across all pages."""
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        yield from page.get(key, [])


# Constants
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MS SQL",
    1521: "Oracle DB",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
}
RESET = "\033[0m"


# Cache instance name lookups
_instance_name_cache: Dict[str, Optional[str]] = {}

def _get_instance_name_cached(instance: Dict[str, Any]) -> Optional[str]:
    """Cache instance name lookups to avoid repeated tag scanning."""
    instance_id = instance.get("InstanceId")
    if instance_id in _instance_name_cache:
        return _instance_name_cache[instance_id]
    
    name = None
    for tag in instance.get("Tags", []):
        if tag.get("Key") == "Name":
            name = tag.get("Value")
            break
    
    _instance_name_cache[instance_id] = name
    return name


def check_imdsv1(session: boto3.Session) -> List[Finding]:
    """Flag instances that haven't enforced IMDSv2."""
    findings: List[Finding] = []
    ec2 = session.client("ec2")

    try:
        reservations = list(paginate(ec2, "describe_instances", "Reservations"))
    except ClientError as e:
        logger.error("Could not describe instances: %s", e)
        return findings

    for reservation in reservations:
        for inst in reservation.get("Instances", []):
            instance_id = inst.get("InstanceId", "unknown")
            metadata_opts = inst.get("MetadataOptions", {})
            http_tokens = metadata_opts.get("HttpTokens", "optional")

            if http_tokens != "required":
                name = _get_instance_name_cached(inst)
                findings.append(
                    Finding(
                        title="IMDSv1 Enabled (IMDSv2 Not Enforced)",
                        severity="CRITICAL",
                        resource_id=f"{instance_id} ({name})" if name else instance_id,
                        resource_type="EC2 Instance",
                        description=(
                            f"Instance {instance_id} has HttpTokens set to '{http_tokens}', "
                            "meaning the legacy metadata service (IMDSv1) is still accessible. "
                            "IMDSv1 is vulnerable to SSRF-based credential theft."
                        ),
                        remediation=(
                            "Enforce IMDSv2 by setting HttpTokens to 'required': "
                            "aws ec2 modify-instance-metadata-options "
                            f"--instance-id {instance_id} --http-tokens required --http-endpoint enabled"
                        ),
                    )
                )

    return findings


def check_security_groups(session: boto3.Session) -> List[Finding]:
    """Look for security groups that allow broad inbound traffic on sensitive ports"""
    findings: List[Finding] = []
    ec2 = session.client("ec2")

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        logger.error("Could not describe security groups: %s", e)
        return findings

    for sg in sgs:
        sg_id = sg.get("GroupId", "unknown")
        sg_name = sg.get("GroupName", "unnamed")

        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
            cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]

            open_to_world = any(c in ("0.0.0.0/0", "::/0") for c in cidrs)
            if not open_to_world:
                continue

            protocol = perm.get("IpProtocol", "")
            if protocol == "-1":
                findings.append(
                    Finding(
                        title="Security Group Allows ALL Traffic from Internet",
                        severity="CRITICAL",
                        resource_id=f"{sg_id} ({sg_name})",
                        resource_type="EC2 Security Group",
                        description=(
                            f"Security group {sg_id} ({sg_name}) allows ALL inbound traffic "
                            "from the internet, exposing all attached instances."
                        ),
                        remediation=(
                            "Remove the rule immediately and scope inbound rules to specific ports/cidrs."
                        ),
                    )
                )
                continue

            if from_port is None or to_port is None:
                continue

            for port, service_name in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append(
                        Finding(
                            title=f"{service_name} (port {port}) Open to Internet",
                            severity="HIGH",
                            resource_id=f"{sg_id} ({sg_name})",
                            resource_type="EC2 Security Group",
                            description=(
                                f"Security group {sg_id} ({sg_name}) allows inbound {service_name} "
                                f"(port {port}) from the internet."
                            ),
                            remediation=(
                                "Restrict inbound access to known CIDRs; consider SSM Session Manager "
                                "for SSH/RDP access."
                            ),
                        )
                    )

    return findings


def _check_policy_document(doc: Dict[str, Any], role_name: str, policy_name: str, issues: List[Dict[str, str]]) -> None:
    """this scans a single policy document for wildcard actions"""
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            if action == "*":
                issues.append(
                    {
                        "title": "EC2 Instance Role Has Wildcard (*) Action",
                        "severity": "HIGH",
                        "description": (
                            f"IAM role '{role_name}' has policy '{policy_name}' with Action '*' "
                            "granting full access to AWS APIs."
                        ),
                        "remediation": (
                            "Use least privilege policies focused on required actions."
                        ),
                    }
                )
                return


def _evaluate_role_policies(iam: Any, role_name: str) -> List[Dict[str, str]]:
    """this one checks attached and inline policies on an IAM role for broad access"""
    issues: List[Dict[str, str]] = []

    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    except ClientError:
        return issues

    for policy in attached:
        policy_arn = policy.get("PolicyArn")
        if policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess":
            issues.append(
                {
                    "title": "EC2 Instance Role Has AdministratorAccess",
                    "severity": "CRITICAL",
                    "description": (
                        f"IAM role '{role_name}' has AdministratorAccess attached."
                    ),
                    "remediation": (
                        "Replace with scoped policies and use IAM Access Analyzer."
                    ),
                }
            )
            continue

        if not policy_arn:
            continue

        try:
            policy_version = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)["PolicyVersion"]["Document"]
        except ClientError:
            continue

        _check_policy_document(policy_doc, role_name, policy.get("PolicyName", "unknown"), issues)

    try:
        inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError:
        return issues

    for policy_name in inline_names:
        try:
            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
        except ClientError:
            continue

        _check_policy_document(policy_doc, role_name, policy_name, issues)

    return issues


def check_ec2_iam_roles(session: boto3.Session) -> List[Finding]:
    """Inspect running instances with IAM roles for over-permissive permissions."""
    findings: List[Finding] = []
    ec2 = session.client("ec2")
    iam = session.client("iam")

    try:
        reservations = list(paginate(ec2, "describe_instances", "Reservations"))
    except ClientError as e:
        logger.error("Could not describe instances: %s", e)
        return findings

    checked_roles: Dict[str, List[Dict[str, str]]] = {}
    checked_profiles: Dict[str, List[str]] = {}

    for reservation in reservations:
        for inst in reservation.get("Instances", []):
            instance_id = inst.get("InstanceId", "unknown")
            profile_arn = inst.get("IamInstanceProfile", {}).get("Arn", "")
            if not profile_arn:
                continue

            profile_name = profile_arn.split("/")[-1]

            if profile_name in checked_profiles:
                for role_name in checked_profiles[profile_name]:
                    issues = checked_roles.get(role_name, [])
                    for issue in issues:
                        findings.append(
                            Finding(
                                title=issue["title"],
                                severity=issue["severity"],
                                resource_id=f"{instance_id} (role: {role_name})",
                                resource_type="EC2 Instance / IAM Role",
                                description=issue["description"],
                                remediation=issue["remediation"],
                            )
                        )
                continue

            try:
                profile_resp = iam.get_instance_profile(InstanceProfileName=profile_name)
                roles = profile_resp["InstanceProfile"].get("Roles", [])
            except ClientError as e:
                logger.error("Could not inspect instance profile %s: %s", profile_name, e)
                continue

            checked_profiles[profile_name] = []
            for role in roles:
                role_name = role.get("RoleName")
                if not role_name:
                    continue

                checked_profiles[profile_name].append(role_name)

                if role_name in checked_roles:
                    issues = checked_roles[role_name]
                else:
                    issues = _evaluate_role_policies(iam, role_name)
                    checked_roles[role_name] = issues

                for issue in issues:
                    findings.append(
                        Finding(
                            title=issue["title"],
                            severity=issue["severity"],
                            resource_id=f"{instance_id} (role: {role_name})",
                            resource_type="EC2 Instance / IAM Role",
                            description=issue["description"],
                            remediation=issue["remediation"],
                        )
                    )

    return findings


def check_ebs_encryption(session: boto3.Session) -> List[Finding]:
    """Flag any EBS volumes that are not encrypted."""
    findings: List[Finding] = []
    ec2 = session.client("ec2")

    try:
        volumes = list(paginate(ec2, "describe_volumes", "Volumes"))
    except ClientError as e:
        logger.error("Could not describe EBS volumes: %s", e)
        return findings

    for vol in volumes:
        if not vol.get("Encrypted", False):
            vol_id = vol.get("VolumeId", "unknown")
            attachments = vol.get("Attachments", [])
            attached_to = attachments[0].get("InstanceId", "unattached") if attachments else "unattached"

            findings.append(
                Finding(
                    title="Unencrypted EBS Volume",
                    severity="MEDIUM",
                    resource_id=f"{vol_id} (attached to: {attached_to})",
                    resource_type="EBS Volume",
                    description=(
                        f"EBS volume {vol_id} is not encrypted, increasing risk of data exposure."
                    ),
                    remediation=(
                        "Enable EBS encryption by default and replace the volume with an encrypted snapshot copy."
                    ),
                )
            )

    return findings


def check_public_ips(session: boto3.Session) -> List[Finding]:
    """Flag instances with public IP addresses."""
    findings: List[Finding] = []
    ec2 = session.client("ec2")

    try:
        reservations = list(paginate(ec2, "describe_instances", "Reservations"))
    except ClientError as e:
        logger.error("Could not describe instances: %s", e)
        return findings

    for reservation in reservations:
        for inst in reservation.get("Instances", []):
            instance_id = inst.get("InstanceId", "unknown")
            public_ip = inst.get("PublicIpAddress")
            if public_ip:
                name = _get_instance_name_cached(inst)
                findings.append(
                    Finding(
                        title="EC2 Instance Has a Public IP Address",
                        severity="LOW",
                        resource_id=f"{instance_id} ({name})" if name else instance_id,
                        resource_type="EC2 Instance",
                        description=(
                            f"Instance {instance_id} has public IP {public_ip}, which may be unnecessary."
                        ),
                        remediation=(
                            "Move the instance to a private subnet or use NAT for egress-only access."
                        ),
                    )
                )

    return findings


def print_report(findings: List[Finding]) -> None:
    """Print findings to stdout ordered by severity."""
    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))

    print("=" * 72)
    print("  EC2 MISCONFIGURATION SCAN RESULTS")
    print(f"  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 72)

    if not sorted_findings:
        print("\n  No misconfigurations found. Nice work.\n")
        return

    counts: Dict[str, int] = {}
    for f in sorted_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n  Total findings: {len(sorted_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"    {color}{sev}{RESET}: {counts[sev]}")

    print()

    for i, f in enumerate(sorted_findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "")
        print(f"  [{color}{f.severity}{RESET}] Finding #{i}: {f.title}")
        print(f"    Resource:    {f.resource_id} ({f.resource_type})")
        print(f"    Description: {f.description}")
        print(f"    Remediation: {f.remediation}")
        print()

    print("=" * 72)


def export_json(findings: List[Finding], filepath: str) -> None:
    """Write findings to a JSON file."""
    data = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }

    with open(filepath, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)

    logger.info("Results exported to %s", filepath)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan an AWS account for common EC2 security misconfigurations."
    )
    parser.add_argument("--region", default=None, help="AWS region to scan (default: session default)")
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    parser.add_argument("--json", dest="json_out", default=None, help="Export results to JSON file")
    args = parser.parse_args()

    session = get_boto_session(profile=args.profile, region=args.region)

    all_findings: List[Finding] = []
    checks = [
        ("IMDSv1 Configuration", check_imdsv1),
        ("Security Group Rules", check_security_groups),
        ("EC2 IAM Role Permissions", check_ec2_iam_roles),
        ("EBS Volume Encryption", check_ebs_encryption),
        ("Public IP Exposure", check_public_ips),
    ]

    for check_name, check_fn in checks:
        logger.info("Running check: %s", check_name)
        try:
            results = check_fn(session)
            all_findings.extend(results)
            logger.info("Found %d issue(s).", len(results))
        except Exception as e:
            logger.exception("Check %s failed with unexpected error", check_name)

    print()
    print_report(all_findings)

    if args.json_out:
        export_json(all_findings, args.json_out)


if __name__ == "__main__":
    main()
