---
layout: default
---

# Malware Analysis & DFIR Tips

Showcasing malware analysis techniques on various samples, plus general DFIR tips & tricks to aid investigations.

The tools I use are freely available — most come pre-installed with **FLARE VM**.

All samples are available on [VirusTotal](https://www.virustotal.com/) / [MalwareBazaar](https://bazaar.abuse.ch/).

## Example Python Snippet

```python
octal_values = [70, 62, 64, 60, 61]
ascii_chars_from_octal = ''.join([chr(int(str(num), 8)) for num in octal_values])
print(ascii_chars_from_octal)
