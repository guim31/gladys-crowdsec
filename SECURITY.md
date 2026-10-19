# Security policy

## Reporting a vulnerability

Please do **not** report a security problem in a public issue, pull request or
forum post.

Report it privately through GitHub instead: open the **Security** tab of this
repository, then **Report a vulnerability**.

No such button? Private reporting is not enabled yet: open an issue that only
asks the maintainers for a private contact, without any detail of the problem,
and send the report there.

Include, when you can:

- the version of the integration and of Gladys;
- what an attacker can do, and the steps to reproduce it;
- the log lines that help (remove tokens, passwords and addresses first).

The fix ships as a new version of the integration, and the advisory is
published once users can update.

## Supported versions

Only the latest release receives security fixes: update the integration from
Gladys before reporting a problem.

## Scope

In scope: the code of this repository and the Docker image it publishes.

The integration stores in Gladys (not in the container) the address of the
CrowdSec Local API, the bouncer key and, optionally, the login and password of
a machine account. Under `/data` it only keeps the highest decision and alert
ids already seen, the last scenario and whether the Local API answered. It
talks to the Local API only, on the local network; nothing goes to the
internet. The bouncer key is read-only; the machine account can delete
decisions, and the integration only does it from the "Delete a decision"
scene action, disabled by default. Keys, passwords, tokens and full IP
addresses never reach the logs at the info level.

Out of scope: Gladys Assistant itself (see its
[security policy](https://github.com/GladysAssistant/Gladys/security/policy)),
and CrowdSec and the other third-party services the integration talks to.
