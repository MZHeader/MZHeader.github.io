---
description: Between May 2024 and January 2026, threat actors have been observed targetting Steam users by uploading malicious games to the Steam platform. At the time of writing, the FBI are currently investigating this. Affected games include BlockBlasters, Chemia, Dashverse/DashFPS, Lampy, Lunara, PirateFi, and Tokenova. In this post, we are reverse engineering PirateFi.
---

## Picking Apart PirateFi: Steam Game Malware

In February 2025, a new game hit the steam marketplace in beta, titled "PirateFi". The free to play game was somewhat underwhelming, due to the fact it was uploaded in order to steam victims information and hijack user accounts.

The game was taken down from Steam marketplace, but the change history can be found here: https://steamdb.info/app/3476470/history/

Upon review, Changelist #27351505 caught my eye due to the following line, showing a heavily embedded vbs script being added:

![Image](https://github.com/MZHeader/MZHeader.github.io/blob/main/assets/2026-03-15%2013_30_44-Desktop%20-%20File%20Explorer.png)

