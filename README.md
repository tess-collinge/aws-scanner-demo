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
[+] Authenticated as: arn:aws:iam::123456789012:user/test-user
[+] Account: 123456789012
[+] Region:  us-east-1

[*] Running check: IMDSv1 Configuration...
    Found 2 issue(s).
[*] Running check: Security Group Rules...
    Found 3 issue(s).
[*] Running check: EC2 IAM Role Permissions...
    Found 1 issue(s).
[*] Running check: EBS Volume Encryption...
    Found 4 issue(s).
[*] Running check: Public IP Exposure...
    Found 2 issue(s).

========================================================================
  EC2 MISCONFIGURATION SCAN RESULTS
  2026-03-22 12:14:32 UTC
========================================================================

  Total findings: 12
    CRITICAL: 3
    HIGH: 3
    MEDIUM: 4
    LOW: 2

  [CRITICAL] Finding #1: IMDSv1 Enabled (IMDSv2 Not Enforced)
    Resource:    i-0abc123def456 (web-server-prod) (EC2 Instance)
    Description: Instance i-0abc123def456 has HttpTokens set to 'optional',
                 meaning the legacy metadata service (IMDSv1) is still accessible.
                 IMDSv1 is vulnerable to SSRF-based credential theft, as
                 demonstrated in the 2019 Capital One breach.
    Remediation: Enforce IMDSv2 by setting HttpTokens to 'required':
                 aws ec2 modify-instance-metadata-options
                 --instance-id i-0abc123def456 --http-tokens required
                 --http-endpoint enabled

  [HIGH] Finding #2: SSH (port 22) Open to Internet
    Resource:    sg-0123456789abcdef (default) (EC2 Security Group)
    Description: Security group sg-0123456789abcdef (default) allows inbound
                 SSH traffic (port 22) from 0.0.0.0/0. This exposes the
                 service to brute-force and scanning attacks.
    Remediation: Restrict port 22 to known CIDR ranges (VPN, office IP).
                 For SSH, consider replacing direct access with AWS Systems
                 Manager Session Manager.

  ...
========================================================================
```

With `--json`, you get something like:

```json
{
  "scan_time": "2026-03-22T12:18:03Z",
  "total_findings": 12,
  "findings": [
    {
      "title": "IMDSv1 Enabled (IMDSv2 Not Enforced)",
      "severity": "CRITICAL",
      "resource_id": "i-0abc123def456 (web-server-prod)",
      "resource_type": "EC2 Instance",
      "description": "Instance i-0abc123def456 has HttpTokens set to ...",
      "remediation": "Enforce IMDSv2 by setting HttpTokens to 'required': ...",
      "timestamp": "2026-03-22T14:30:00Z"
    }
  ]
}
```