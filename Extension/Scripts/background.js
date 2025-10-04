// Define the Sleep Function:
// const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// List of the last checked urls, so the api rate would'nt exceed:
let checked_urls = [];
const checked_urls_max_length = 30;

// List of the last unsafe websites, so it would'nt send the notification twice:
let known_unsafe_urls = []; 
const known_unsafe_urls_max_length = 5;

// What score does a site need to be considered unsafe? -- VirusTotal Score
const unsafe_site_score = 2;

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------

// Google Safe Browsing Lookup API:
let google_api_key = "";
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
        } else if (data){
        return { safe: true};
        }else{
            return{safe: null};
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
let virustotal_api_key = "";
const virustotal_api_url = "https://www.virustotal.com/api/v3/urls/"

async function checkUrl_virustotal(url) {
    const url_encoded = btoa(url).replace(/=/g, ''); 
    const full_url = virustotal_api_url+url_encoded;

    try {
        const res = await fetch(full_url, {
            method: 'GET',
            headers: { 
                'x-apikey': virustotal_api_key,
                'Accept': 'application/json' 
            }
        });

        if (res.status === 404) {
            // URL not found in database
            return { safe: null, info: "Not in database" };
        }

        if (res.status === 429) {
            // Rate limit exceeded (4 requests/minute)
            console.error("VirusTotal API Rate Limit Hit (429)");
            return { safe: null, error: "API Rate Limit" };
        }

        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }

        const data = await res.json();
        const stats = data.data.attributes.last_analysis_stats;

        const detected_count = stats.malicious + stats.suspicious;
        const harmless_count = stats.harmless;
        const ratio_string = `${detected_count}/${harmless_count}`;
        
        // A URL is considered unsafe if any scanner marked it as malicious or suspicious
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
    if(msg.action==="updateApiKeys"){
        // Load secrets in background script
        fetch(chrome.runtime.getURL('Scripts/secret.json'))
        .then((response) => response.json())
        .then((secrets) => {
            virustotal_api_key = secrets.VIRUSTOTAL_APIKEY;
            google_api_key = secrets.GOOGLE_APIKEY;
        })
        .catch((err) => {
            console.error('Failed to load secret.json:', err);
        });

    }
    if (msg.action === "isCheckedUrl" && msg.url){
        sendResponse(is_checked(msg.url))
    }

    if (msg.action === "getResult" && msg.url) {
        if(msg.url===result.url){
            sendResponse(result);
        } else {
            sendResponse(undefined);
        }
    }

    if (msg.action === "checkPhish" && msg.url) {
        (async () => {
            checked_urls.push(msg.url);
            while (checked_urls.length>checked_urls_max_length){
                checked_urls.shift();
            }
            const google_res = await checkUrl_google(msg.url || "");
            const virustotal_res = await checkUrl_virustotal(msg.url || "");

        // Sends a notifiaction to an unsafe site (unsafe_site_score - virustotal), or google flags it as unsafe 
        if(virustotal_res.malicious+virustotal_res.suspicious>=unsafe_site_score || !google_res.safe){
            // Checks if the site is not in the last 10 urls
            if (!known_unsafe_urls.includes(msg.url)){
                createAlertNotification(msg.url, virustotal_res.score, google_res.safe);
                known_unsafe_urls.push(msg.url);
                while(known_unsafe_urls.length>known_unsafe_urls_max_length){
                    known_unsafe_urls.shift();
                }
            }
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

// Checks if a url has been checked recently:
function is_checked(url){
    return checked_urls.includes(url);
}

// Sends a notification that the site is unsafe
function createAlertNotification(url, score, googleStatus) {
    const title = "The Website You Just Entered is Potentially Unsafe";
    const message = `URL: ${url}\nVirusTotal score: ${score}\nGoogle: ${googleStatus}`;

    chrome.notifications.create(
        undefined,
        {
        type: "basic",
        iconUrl: "/Images/Logo1.png",
        title,
        message,
        priority: 2 
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