# Safe-Browsing-Chrome-Extension
A chrome etxtension that protects you from phishing and social engeneering attacks.

## Databases & API's:
  1. [**Google Lookup API** v4/v5](https://developers.google.com/safe-browsing/v4) - industry-grade blacklist for phishing/malware, can be used as a real-time lookup.<br>
  ~~2. [**PhishTank**](https://phishtank.org/) (Open community feed + API) - API Problems~~<br>
  3. [**VirusTotal**](https://docs.virustotal.com/) (URL / domain reports & scans) — aggregates many AV/URL scanners and reputation sources; great as a second-opinion API.<br>
  ~~4. [**urlscan.io**](https://urlscan.io/docs/api/) - submit URLs and get a DOM snapshot, resource list, screenshots and (paid) phishing/brand-detection feeds — very useful to analyze page contents safely off-client. - Not Effective, Is'nt Implemented~~<br>

## Features:
  1. Automaticly checks the site Url, and sends it to the above APIs.<br>
  2. Displayes the result in the extension.<br>
  3. If a site is found unsafe, a messege is sent to the user.<br>
  4. API flooding control - doesn't automaticly checks the site if it has been checked recently.<br>
