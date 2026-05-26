# Security Policy

## Reporting a Vulnerability

Please do not report security vulnerabilities through public issues.

Send a private report to the repository owner with:

- affected version or commit
- operating system and shell
- reproduction steps
- expected and actual behavior
- any logs with secrets removed

Use fake values in examples. Do not include real `.kagi/` directories, master
keys, decrypted secrets, or production `.env` files in reports.

## Scope

Security-sensitive areas include encryption, authenticated data handling,
master-key loading, file permissions, non-interactive secret output, command
execution through `kagi run`, and path handling for nested projects.
