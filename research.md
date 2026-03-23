# EC2 Security Analysis: Misconfigurations and Attack Surface

## Overview

EC2 (Elastic Compute Cloud) is AWS's core compute service, providing virtual machines on demand. An administrator picks an OS, an instance size, attach storage (EBS volumes), and drops it into the VPC. From a security perspective, EC2 is where a lot of different things converge: networking through security groups, identity through IAM roles, storage through EBS, and the instance metadata service (IMDS) which hands out credentials at runtime.

EC2 is usually where your actual workloads run, which makes it a common attack target. An attacker's goals almost always boil down to getting a shell, stealing creds, moving laterally, or exfiltrating data, all of which EC2 commonly touches.

EC2 instances tend to be interesting from an offensive angle because they're often directly internet facing and running web apps. They frequently have IAM roles attached (meaning a compromise gives you access to other AWS services), and their metadata service will hand out credentials to anyone who can reach it if IMDSv1 is still active.

The main targets within EC2 are the instances themselves, the IAM roles attached to them, the EBS volumes where data lives, security groups controlling network access, and the metadata service.


## Misconfigurations (Ranked by Severity)

### 1. Instance Metadata Service v1 (IMDSv1) Still Enabled

**Risk: Critical**

IMDS runs on a link-local address and gives instances information about themselves - most critically, temporary IAM credentials. With IMDSv1, getting those credentials is a single unauthenticated GET request.

The 2019 Capital One breach is a textbook case. A misconfigured WAF had an SSRF flaw. The attacker (a former AWS employee, incidentally) exploited it to query the metadata service, stole the IAM role credentials, and used them to access over 700 S3 buckets. 106 million customer records were exposed. The fine was $80 million, and the total cost was around $270 million when including remediation, a class action settlement, and legal costs.

IMDSv2 fixes this by adding a token requirement. A PUT request is made to get a session token, then that token is included in subsequent GET requests. This breaks SSRF because SSRF vulnerabilities almost never allow the issuance of PUT requests, they're almost always limited to GET. On top of that, the token has a TTL of 1 hop, so even if it's somehow acquired, it can't leave the instance. AWS made IMDSv2 the default for new instances in late 2023, but a large number of existing instances are still running v1. Research from 2022 put the number at roughly 93% of instances not enforcing v2, and while that's improved, it's still very common in the wild.

**Attack Scenario:** Using `curl http://[IP]/latest/meta-data/iam/security-credentials/<role-name>` can return back working AWS keys. If anything on the instance has a Server-Side Request Forgery (SSRF) vulnerability, an attacker can make the application fetch that URL for them. The app hits the metadata endpoint, gets the credentials, and returns them to the attacker. From there, the attacker takes those keys to their own machine and uses them to access whatever the IAM role allows.

**Remediation:** Enforce IMDSv2 by setting `HttpTokens` to `required` on all instances. You can do this per-instance with `aws ec2 modify-instance-metadata-options`, or enforce it org-wide with the `ec2:MetadataHttpTokens` condition key in a Service Control Policy so nobody can launch instances with v1 enabled. The `MetadataNoToken` CloudWatch metric is useful for tracking remaining v1 usage before you flip the switch.


### 2. Overly Permissive Security Groups (SSH/RDP/DB Ports Open to 0.0.0.0/0)

**Risk: High**

Security groups are basically per-instance firewalls. The classic misconfiguration is leaving port 22 (SSH) or 3389 (RDP) open to `0.0.0.0/0` -- the entire internet.

This one happens all the time because someone opens SSH for a quick debugging session, forgets to close it, and now it's permanent. Within minutes of port 22 being exposed, automated bots start hitting it with credential stuffing attacks. If password auth is enabled (it shouldn't be, but it often is), you're one weak password away from full compromise. Even with key-based auth, you've expanded your attack surface for no reason.

Database ports are arguably worse. Having 3306 (MySQL), 5432 (PostgreSQL), or 1433 (MS SQL) open to the internet is a direct line to your data. I don't think I need to explain why that's bad.

**Attack scenario:** Attacker scans for open SSH. Finds your instance. If password auth is on, they run credential stuffing with leaked password lists. If not, they at least know the instance exists and start looking for other services. An open security group tends to correlate with other sloppy configs, so it's worth poking at.

**Remediation:** Restrict SSH/RDP to known CIDRs (your VPN, your office IP). Even better, drop SSH entirely and use AWS Systems Manager Session Manager, which tunnels through the AWS control plane and means you don't need an open inbound port at all. For service-to-service communication inside your VPC, use security group references instead of IP ranges. And set up AWS Config rules (`restricted-ssh`, `restricted-common-ports`) to catch these automatically.


### 3. Overly Permissive IAM Roles on EC2 Instances

**Risk: High**

When you attach an IAM role to an instance, every process on that machine can use those permissions. Teams almost always give roles more access than the workload actually needs, because it's easier to slap `s3:*` on there than to figure out which specific buckets and operations the app requires.

If the instance gets compromised, the attacker's blast radius is whatever the role permits. A tightly scoped role limits damage to one bucket. A role with `*:*` gives the attacker the keys to the entire account.

**Attack Scenario:** This is what made the Capital One breach so devastating. The SSRF gave initial access, IMDSv1 let them steal creds, but the real damage came from the IAM role being able to list and read S3 buckets it shouldn't have been touching. A WAF role shouldn't need S3 access. If it had been properly scoped, the stolen credentials would have been mostly useless.

**Remediation:** Least privilege. Scope policies to specific resources and actions. Use IAM Access Analyzer to find unused permissions and generate right-sized policies from actual CloudTrail usage. Never attach `AdministratorAccess` or `*:*` policies to instance roles -- it happens more than you'd think, and there's never a good reason for it on an application workload. Permission boundaries are also useful as guardrails for delegated role creation.


### 4. Unencrypted EBS Volumes

**Risk: Medium-High**

EBS volumes are the disks attached to EC2 instances. Without encryption, everything on them is stored in plaintext: application data, database files, secrets, and logs.

Unencrypted volumes produce unencrypted snapshots, and snapshots can be shared across accounts or even made public.

**Attack Scenario:** If an attacker has enough access to an AWS account to describe and copy snapshots, they can copy an unencrypted snapshot to their own account, spin up a volume from it, mount it, and read everything. This includes anything that was on that disk, like application secrets, SSH keys, or database dumps.

**Remediation:** EBS encryption should be on by default at the account level with `aws ec2 enable-ebs-encryption-by-default`. New volumes will be encrypted automatically. For existing unencrypted volumes, you have to do a snapshot-copy-replace dance (snapshot the volume, copy the snapshot with encryption, create a new volume from the encrypted copy). AWS-managed KMS keys work fine for most cases; customer-managed keys give you more control if you need it. The `encrypted-volumes` AWS Config rule handles ongoing auditing.


### 5. EC2 Instances with Unnecessary Public IPs

**Risk: Medium**

This one is less of a vulnerability on its own and more of an attack surface issue. A lot of environments auto-assign public IPs to instances at launch, or put instances in public subnets out of habit. Every public IP is something an attacker can scan and probe.

AWS publishes their IP ranges, so attackers know exactly which IPs belong to EC2. Scanning for exposed services on those ranges is trivial and happens constantly.

**Attack Scenario:** An attacker would be able to perform any of the other attacks with ease when a public IP is added without need.

**Remediation:** If an instance doesn't need to be directly reachable from the internet, it shouldn't have a public IP. It should be in a private subnet with a load balancer in front of it if it serves web traffic, and any affected instances should use a NAT gateway for outbound access. For admin access, use SSM Session Manager instead of SSH to a public IP.

## References Reviewed

### IMDSv1 / Capital One Breach

1. Krebs Article on Capital One Breach
   https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/

2. Research Article: Lessons Learned on Capital One Breach
   https://dl.acm.org/doi/full/10.1145/3546068

3. $80 Million Civil Money Penalty Against Capital One
   https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html

4. SEC Press Release
   https://www.sec.gov/Archives/edgar/data/0000927628/000092762819000262/exhibit991-pressrelease72919.htm

5. Capital One $190 Million Breach Settlement
   https://www.mvalaw.com/data-points/capital-one-reaches-190-million-settlement-in-connection-with

6. An SSRF, privileged AWS keys and the Capital One breach
   https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af

### IMDSv2 Default / Migration

7. IMDSv2 by Default
   https://aws.amazon.com/blogs/aws/amazon-ec2-instance-metadata-service-imdsv2-by-default/

8. The full benefits of IMDSv2 and disabling IMDSv1
   https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/

### SSH Brute Force / Security Groups

9. An Analysis of SSH attacks on Amazon EC2
    https://blog.smarthoneypot.com/in-depth-analysis-of-ssh-attacks-on-amazon-ec2/

10. GuardDuty and Brute Force Attacks
    https://repost.aws/knowledge-center/identify-attacks-with-guardduty

11. Securing SSH on EC2
    https://www.sysdig.com/blog/aws-secure-ssh-ec2-threats

### EBS Snapshot Exfiltration

12. Stealing an EBS snapshot
    https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/sharing-ebs-snapshot/

13. Amazon EBS encryption
    https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html

### IAM Least Privilege / Access Analyzer

14. IAM Access Analyzer
    https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/

### AWS IP Ranges

15. AWS IP address ranges
    https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html