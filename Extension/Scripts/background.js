// Google Safe Browsing Lookup API
const google_api_key = "AIzaSyBgC0tLgH-C1xewijMspmtsaHWpQzDTSng";
const google_api_url = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${google_api_key}`;

async function checkUrl_google(url) {
    const body = {
        client: {
        clientId: "safe-browsing-extension",
        clientVersion: "1.0"
        },
        threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
        }
    };

    try {
        const res = await fetch(google_api_url, {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        if (data && data.matches) {
        return { safe: false, matches: data.matches };
        } else {
        return { safe: true };
        }
    } catch (err) {
        console.error(err);
        return { safe: false, error: "API request failed" };
    }
}

// PhishTank API:
// TODO: Get an API key
const phishtank_api_url = `https://checkurl.phishtank.com/checkurl/`;

async function checkUrl_phishtank(url) {
    const body = new URLSearchParams();
    body.append("url", url);
    body.append("format", "json");

    try {
        const res = await fetch(phishtank_api_url, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "phishtank/safe-browsing-extension" 
            },
            body: body.toString()
        });

        const data = await res.json();

        if (data && data.results) {
            if (data.results.in_database && data.results.valid) {
                return { safe: false, info: data.results };
            } else {
                return { safe: true, info: data.results };
            }
        } else {
            return { safe: false, error: "Unexpected API response" };
        }
    } catch (err) {
        console.error(err);
        return { safe: false, error: "API request failed" };
    }
}


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.action === "checkPhish" && message.url) {
        // call the async function and respond asynchronously
        (async () => {
        const phishtank_res = await checkUrl_phishtank(message.url || "");
        const google_res = await checkUrl_google(message.url || "");
        // sendResponse works only if we return true below
        const response = "Google: " + google_res + "PhishTank: " + phishtank_res
        sendResponse({response});
    })();
        // Return true to indicate we'll call sendResponse asynchronously.
        return true;
    }
});