# 05 — Data Access and Persistence

## Objective

Document post-exploitation access to sensitive files and persistence indicators, including the honeyfile detection point.

## Commands

From the controlled reverse shell, collect only the lab evidence:

```bash
id
cat /etc/passwd
ls -l /var/www/app/backup_credentials.txt
cat /var/www/app/backup_credentials.txt
```

```bash
crontab -l
ls -la /etc/cron.d
```

## Execution and expected result

Reading the honeyfile should generate a high-severity or critical Wazuh alert. Document the files accessed, the account used, and the resulting alert:

```text
Paste the execution result here.
```

Do not include real credentials or secrets in this document.

## Wazuh view

Verify the alert contains:

- the monitored honeyfile path;
- the process and user that accessed it;
- the source host and timestamp;
- the configured severity and rule ID.

Also review file integrity events for unexpected changes to startup files or application files.

## Mitigation

- Remove real secrets from the filesystem and rotate any exposed credentials.
- Store secrets in a dedicated secret manager or protected environment configuration.
- Restrict file permissions using least privilege.
- Monitor sensitive files with Wazuh FIM and a dedicated honeyfile rule.
- Disable unauthorized scheduled tasks and review persistence locations regularly.
- Isolate and rebuild a compromised host rather than trusting manual cleanup.