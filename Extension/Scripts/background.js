// Define the Sleep Function:
// const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

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
        return { safe: null, error: "API request failed" +err};
    }
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------

// PhishTank API: Not Working
// TODO: Get an API key
// const phishtank_api_url = `https://checkurl.phishtank.com/checkurl/index.php`;

// async function checkUrl_phishtank(url) {    
//     const params = new URLSearchParams();
//     params.append('url', url);
//     params.append('format', 'json');
//     //params.append('app_key', PHISHTANK_API_KEY);

//     try {
//         const response = await fetch(phishtank_api_url, {
//         method: 'POST',
//         headers: {
//             // 1. Set the recommended User-Agent string
//             'User-Agent': `phishtank/firesodlier (Chrome Extension)`,
            
//             // 2. PhishTank API is a POST request that typically uses x-www-form-urlencoded
//             'Content-Type': 'application/x-www-form-urlencoded', 
//         },
//         // Send the parameters in the request body
//         body: params.toString() 
//         });

//         if (response.status === 403) {
//             console.error("PhishTank API returned 403 Forbidden. Check your API key and User-Agent.");
//             return {info: "403"};
//         }

//         if (!response.ok) {
//             throw new Error(`HTTP error! status: ${response.status}`);
//         }

//         const data = await response.json();
//         return {safe: data.result.safe};

//     } catch (error) {
//         console.error("Error calling PhishTank API:", error);
//         return null;
//     }
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------

//Virus Total:
const virustotal_api_key = "9eb385aba130cf0802efa162736d749df942121ed75d6584b6738fb8c995efd9";
const virustotal_api_url = "https://www.virustotal.com/api/v3/urls/"

async function checkUrl_virustotal(url) {
    // 1. VirusTotal uses a Base64-encoded, unpadded URL as the resource identifier (ID)
    const url_encoded = btoa(url).replace(/=/g, ''); 
    const full_url = virustotal_api_url+url_encoded;

    try {
        const res = await fetch(full_url, {
            method: 'GET',
            headers: { 
                // Authentication uses the x-apikey header
                'x-apikey': virustotal_api_key,
                'Accept': 'application/json' 
            }
        });

        if (res.status === 404) {
            // URL not found in VT's database; treat as safe for this check.
            return { safe: true, info: "Not scanned recently" };
        }

        if (res.status === 429) {
            // Rate limit exceeded (4 requests/minute for Public API)
            console.error("VirusTotal API Rate Limit Hit (429)");
            return { safe: null, error: "Rate Limit" };
        }

        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }

        const data = await res.json();
        // Check 'last_analysis_stats' for malicious/suspicious detections
        const stats = data.data.attributes.last_analysis_stats;

        const detected_count = stats.malicious + stats.suspicious;
        const harmless_count = stats.harmless;
        const ratio_string = `${detected_count}/${harmless_count}`;
        
        // A URL is considered unsafe if any scanner marked it as malicious
        if (stats.malicious > 0 || stats.suspicious > 0) {
            return { safe: false, malicious: stats.malicious, suspicious: stats.suspicious, harmless:stats.harmless, score: ratio_string };
        } else {
            return { safe: true,  malicious: stats.malicious, suspicious: stats.suspicious, harmless:stats.harmless, score: ratio_string };
        }

    } catch (err) {
        console.error("VirusTotal API Error:", err);
        return { safe: null, error: "API request failed"+err };
    }
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------
// urlscan.io:

// urlscan.io API
// TODO: Replace with your actual API key
// const urlscan_api_key = " 0199a5fc-7fa5-772e-8473-7ffb6aed9ef8"; 
// const urlscan_submit_url = "https://urlscan.io/api/v1/scan/"; 
// const urlscan_result_base_url = "https://urlscan.io/api/v1/result/";

// async function checkUrl_urlscan(url) {
//     const submitBody = {
//         url: url,
//         visibility: "unlisted" 
//     };

//     try {
//         // Submit the URL for a new scan:
//         let res = await fetch(urlscan_submit_url, {
//             method: "POST",
//             body: JSON.stringify(submitBody),
//             headers: { 
//                 "Content-Type": "application/json",
//                 "API-Key": urlscan_api_key 
//             }
//         });

//         if (res.status === 429) {
//             console.error("urlscan.io Rate Limit Hit (429)");
//             return { score: null, error: "Rate Limit" }; 
//         }
        
//         if (!res.ok) {
//             throw new Error(`Submission failed with status: ${res.status}`);
//         }

//         const data = await res.json();
//         const uuid = data.uuid;

//         // Poll for the scan results:
//         let resultData = null;
//         await sleep(10000); // Wait 5 seconds
            
//         res = await fetch(`${urlscan_result_base_url}${uuid}/`, {
//             headers: { "API-Key": urlscan_api_key }
//         });

//         if (res.status === 200) {
//             resultData = await res.json();
//         }
//         else {
//             throw new Error(`Result retrieval failed with status: ${res.status}`);
//         }

//         if (!resultData) {
//             // Timeout after polling
//             return { score: null, error: "Timeout" }; 
//         }

//         // Extract the score
//         // Score is an integer from -100 (safe) to 100 (malicious)
//         const urlscan_score = resultData.verdicts.urlscan.score;
        
//         return { 
//             score: urlscan_score 
//         };

//     } catch (err) {
//         console.error("urlscan.io API Error:", err);
//         return { score: null, error: "API request failed" }; 
//     }
// }

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------
let result = "";

// Calling the Functions:
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "getResult") {
        sendResponse(result);
    }

    if (msg.action === "checkPhish" && msg.url) {
        (async () => {
        const google_res = await checkUrl_google(msg.url || "");
        const virustotal_res = await checkUrl_virustotal(msg.url || "");

        if(virustotal_res.malicious+virustotal_res.suspicious>=1){
            createAlertNotification(msg.url, virustotal_res.score, google_res.safe);
            // Optional: set a badge on the extension icon
            try {
                chrome.action.setBadgeText({ text: "!" });
                chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
            } catch (e) {
                // setBadgeText may fail in some contexts; ignore
                console.warn("Badge set failed:", e);
            }
        } else {
            chrome.action.setBadgeText({ text: "" });
        }

        result = {
            url: msg.url,
            google: google_res.safe,
            virustotal: virustotal_res.score,
            error: virustotal_res.error
        };

        sendResponse(result);
    })();
        return true;
    }
});

function createAlertNotification(url, score, googleStatus) {
    const title = "The Website You Just Entered is Potentially Unsafe";
    const message = `URL: ${url}\nVirusTotal score: ${score}\nGoogle: ${googleStatus}`;

    // iconUrl should be a path to an icon inside your extension (48px recommended)
    chrome.notifications.create(
        /*notificationId=*/ undefined,
        {
        type: "basic",
        iconUrl: "/Images/Logo1.png",
        title,
        message,
        priority: 2 // high priority
        },
        notificationId => {
        if (chrome.runtime.lastError) {
            console.error("Notification error: ", chrome.runtime.lastError.message);
        } else {
            console.log("Notification shown, id:", notificationId);
        }
        }
    );
}