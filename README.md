# Safe Browsing Chrome Extension
A chrome etxtension that protects you from phishing and social engeneering attacks.

## Databases & API's:
  1. [**VirusTotal**](https://docs.virustotal.com/) (URL / domain reports & scans)<br>
  2. [**Google Lookup API** v4](https://developers.google.com/safe-browsing/v4)<br>
  3. [**urlscan.io**](https://urlscan.io/docs/api/) <br>


## Features:
  1. Automaticly checks the site Url, and sends it to the above APIs.<br>
  2. Displayes the result in the extension.<br>
  3. If a site is found unsafe, a messege is sent to the user.<br>
  4. API flooding control - doesn't automaticly checks the site if it has been checked recently.<br>

## Set Up API Keys:
  Create a file inside the Scripts folder called secret.json:<br>
  ```json
  {
    "VIRUSTOTAL_APIKEY" : "****",
    "GOOGLE_APIKEY" : "****", 
    "URLSCAN_APIKEY" : "****"
  }
  ```
  Fill out your Google Safe Browsing, Virustotal and Urlscan API keys.
