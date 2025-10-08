# Safe Browsing Chrome Extension
A Chrome extension that protects you from phishing and social engineering attacks.

## Databases & API's:
  1. [**VirusTotal**](https://docs.virustotal.com/) (URL / domain reports & scans)<br>
  2. [**Google Lookup API** v4](https://developers.google.com/safe-browsing/v4)<br>


## Features:
  1. Automatically checks the site URL and sends it to the above APIs.<br>
  2. Displays the result in the extension.<br>
  3. If a site is found unsafe, a message is sent to the user.<br>
  4. Checks the site to see if it has been checked recently. If it has, it doesn't check it again.<br>

## Set Up API Keys:
  Create a file inside the Scripts folder called secret.json:<br>
  ```json
  {
    "VIRUSTOTAL_APIKEY" : "****",
    "GOOGLE_APIKEY" : "****", 
    "URLSCAN_APIKEY" : "****"
  }
  ```
  Fill out your Google Safe Browsing, Virustotal, and Urlscan API keys.
  (UrlScan feature is still a work in progress).
