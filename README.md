# EC2 Security Misconfiguration Scanner

Scans an AWS account for common EC2 security misconfigurations and reports what it finds. Each finding includes a severity level, a description of the misconfigurations that it detects, and how to fix it.

The research writeup (`research.md`) covers the security analysis side, while this tool handles detection for the issues identified there.

## What It Checks

1. **IMDSv1 enabled** instances that aren't enforcing IMDSv2, which makes them vulnerable to SSRF-based credential theft
2. **Overly permissive security groups** SSH, RDP, or database ports open to 0.0.0.0/0
3. **Overly permissive IAM roles** instance roles with wildcard or admin-level permissions
4. **Unencrypted EBS volumes** data at rest stored without encryption
5. **Public IP exposure** instances with public IPs that might not need them

## Prerequisites

- Python 3.11+
- An AWS account with credentials configured
- boto3

### IAM Permissions

Your credentials need read access to EC2, IAM, and EBS. Use the `ReadOnlyAccess` managed policy for testing.

### Configure AWS Credentials

```bash
aws configure
```

Or just export them:

```bash
export AWS_ACCESS_KEY_ID=your-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-east-1
```

## Usage

```
python ec2_misconfig_scanner.py

**Flags**:
--region us-west-2
--profile my-test-account
--json results.json
```

## Example Output

```
========================================================================
  EC2 MISCONFIGURATION SCAN RESULTS
  2026-03-23 05:17:49 UTC
========================================================================

  Total findings: 8
    CRITICAL: 1
    HIGH: 2
    MEDIUM: 3
    LOW: 2

  [CRITICAL] Finding #1: IMDSv1 Enabled (IMDSv2 Not Enforced)
    Resource:   RESOURCE_NAME (misconfig-test-instance) (EC2 Instance)
    Description: Instance RESOURCE_NAME has HttpTokens set to 'optional', meaning the legacy metadata service (IMDSv1) is still accessible. IMDSv1 is vulnerable to SSRF-based credential theft.
    Remediation: Enforce IMDSv2 by setting HttpTokens to 'required': aws ec2 modify-instance-metadata-options --instance-id RESOURCE_NAME --http-tokens required --http-endpoint enabled

  [HIGH] Finding #2: SSH (port 22) Open to Internet
    Resource:    OTHER_SECURITY_GROUP (launch-wizard-1) (EC2 Security Group)
    Description: Security group OTHER_SECURITY_GROUP (launch-wizard-1) allows inbound SSH (port 22) from the internet.
    Remediation: Restrict inbound access to known CIDRs; consider SSM Session Manager for SSH/RDP access.

  [HIGH] Finding #3: SSH (port 22) Open to Internet
    Resource:    SECURITY_GROUP (misconfig-test-sg) (EC2 Security Group)
    Description: Security group SECURITY_GROUP (misconfig-test-sg) allows inbound SSH (port 22) from the internet.
    Remediation: Restrict inbound access to known CIDRs; consider SSM Session Manager for SSH/RDP access.

  [MEDIUM] Finding #4: Unencrypted EBS Volume
    Resource:    vol-06c32120ec2ce5a1f (attached to: OTHER_RESOURCE_NAME) (EBS Volume)
    Description: EBS volume vol-06c32120ec2ce5a1f is not encrypted, increasing risk of data exposure.
    Remediation: Enable EBS encryption by default and replace the volume with an encrypted snapshot copy.

  [MEDIUM] Finding #5: Unencrypted EBS Volume
    Resource:    vol-043b647204386b741 (attached to: unattached) (EBS Volume)
    Description: EBS volume vol-043b647204386b741 is not encrypted, increasing risk of data exposure.
    Remediation: Enable EBS encryption by default and replace the volume with an encrypted snapshot copy.

  [MEDIUM] Finding #6: Unencrypted EBS Volume
    Resource:    vol-03f6eecad9c4c67fe (attached to: RESOURCE_NAME) (EBS Volume)
    Description: EBS volume vol-03f6eecad9c4c67fe is not encrypted, increasing risk of data exposure.
    Remediation: Enable EBS encryption by default and replace the volume with an encrypted snapshot copy.

  [LOW] Finding #7: EC2 Instance Has a Public IP Address
    Resource:    OTHER_RESOURCE_NAME (test) (EC2 Instance)
    Description: Instance OTHER_RESOURCE_NAME has public IP [IP], which may be unnecessary.
    Remediation: Move the instance to a private subnet or use NAT for egress-only access.

  [LOW] Finding #8: EC2 Instance Has a Public IP Address
    Resource:    RESOURCE_NAME (misconfig-test-instance) (EC2 Instance)
    Description: Instance RESOURCE_NAME has public IP [IP], which may be unnecessary.
    Remediation: Move the instance to a private subnet or use NAT for egress-only access.

========================================================================
```