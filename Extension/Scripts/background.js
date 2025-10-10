// Define the Sleep Function:
// const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// List of the last checked urls, so the api rate would'nt exceed:
let checked_urls = [];
const checked_urls_max_length = 30;

// List of the last unsafe websites, so it would'nt send the notification twice:
let known_unsafe_urls = []; 
const known_unsafe_urls_max_length = 5;

// What score does a site need to be considered unsafe? or suspicious? -- VirusTotal Score
const suspicious_site_score = 2;
const unsafe_site_score = 10;

//----------------------------------------------------------------------------------------------------------------------------------------------------------------------

// Google Safe Browsing Lookup API:
let google_api_key = "";
const google_api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";

async function checkUrl_google(url) {
    const google_full_url = google_api_url+google_api_key;
    const body = {
        client: {
        clientId: "safebrowsingextensionn",
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
        const res = await fetch(google_full_url, {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        if (data && data.matches) {
        return { safe: false, matches: data.matches };
        } else {
            return {safe : true};
        }
    } catch (err) {
        console.error("Google API ErrorL " + err);
        return { safe: null, error: "API request failed" +err};
    }
}

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
            return { safe: null, error: "Not in database" };
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
        return { safe: null, error: "API request failed"+ err };
    }
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------------
// urlscan.io:

// TODO: Replace with your actual API key
let urlscan_api_key = ""; 
const urlscan_submit_url = "https://urlscan.io/api/v1/scan/"; 
const urlscan_result_base_url = "https://urlscan.io/api/v1/result/";

// async function checkUrl_urlscan(url) {
//     const submitBody = {
//         url: url,
//         public: "off" 
//     };

//     try {
//         // Submit the URL for a new scan:
//         let res = await fetch(urlscan_submit_url, {
//             method: "POST",
//             headers: { 
//                 "Content-Type": "application/json",
//                 "API-Key": urlscan_api_key 
//             },
//             body: JSON.stringify(submitBody)
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
//         for (let index = 0; index < 6 || res.status === 200; index++) {
//             res = await fetch(`${urlscan_result_base_url}${uuid}/`, {
//                 headers: { "API-Key": urlscan_api_key }
//             });
//             await sleep(3000); // Wait 3 seconds 
//         }

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
        console.log("Updated API Keys")
        // Load secrets in background script
        fetch(chrome.runtime.getURL('Scripts/secret.json'))
        .then((response) => response.json())
        .then((secrets) => {
            virustotal_api_key = secrets.VIRUSTOTAL_APIKEY;
            google_api_key = secrets.GOOGLE_APIKEY;
            // urlscan_api_key = secrets.URLSCAN_APIKEY;
        })
        .catch((err) => {
            console.error('Failed to load secret.json:', err);
        });

    }
    if (msg.action === "isCheckedUrl" && msg.url){
        const res = is_checked(msg.url);
        if (res){
            const item = checked_urls.find(item => item.url === msg.url);
            if(item.level===2){
                if (!known_unsafe_urls.includes(msg.url)){
                    createAlertNotification(msg.url, virustotal_res.score, google_res.safe, 2);
                    known_unsafe_urls.push(msg.url);
                    while(known_unsafe_urls.length>known_unsafe_urls_max_length){
                        known_unsafe_urls.shift();
                    }
                }
                
                chrome.action.setBadgeText({ text: "!" });
                chrome.action.setBadgeBackgroundColor({ color: "#ff0000ff" });
            }
            else if (item.level===1){
                if (!known_unsafe_urls.includes(msg.url)){
                    createAlertNotification(msg.url, virustotal_res.score, google_res.safe, 1);
                    known_unsafe_urls.push(msg.url);
                    while(known_unsafe_urls.length>known_unsafe_urls_max_length){
                        known_unsafe_urls.shift();
                    }
                }
                
                chrome.action.setBadgeText({ text: "!" });
                chrome.action.setBadgeBackgroundColor({ color: "#FFA000" });
            }
            else if(item.level===0){
                chrome.action.setBadgeText({ text: "√" });
                chrome.action.setBadgeBackgroundColor({ color: "#00FF00" });
            }
        }
        sendResponse(res);
    }

    if (msg.action === "getResult" && msg.url) {
        if(msg.url===result.url && result.virustotal!=null){
            sendResponse(result);
        } else {
            sendResponse(undefined);
        }
    }

    if (msg.action === "checkPhish" && msg.url) {
        (async () => {
            const google_res = await checkUrl_google(msg.url);
            const virustotal_res = await checkUrl_virustotal(msg.url);
            // const urlscan_res = await checkUrl_urlscan(msg.url);

            const virustotal_score = virustotal_res.malicious+virustotal_res.suspicious;

        // Sends a notifiaction to an unsafe site (unsafe_site_score - virustotal), or google flags it as unsafe 
        if(virustotal_score>=unsafe_site_score || !google_res.safe){
            // Add to the list with a level of 2
            checked_urls.push({"url" : msg.url, "level": 2});
            while (checked_urls.length>checked_urls_max_length){
                checked_urls.shift();
            }
            
            createAlertNotification(msg.url, virustotal_res.score, google_res.safe, 2);
            known_unsafe_urls.push(msg.url);
            while(known_unsafe_urls.length>known_unsafe_urls_max_length){
                known_unsafe_urls.shift();
            }

            // Set a badge on the extension icon
            try {
                chrome.action.setBadgeText({ text: "!" });
                chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
            } catch (e) {
                // setBadgeText may fail in some contexts; ignore
                console.warn("Badge set failed:", e);
            }
        } else if(virustotal_score>=suspicious_site_score){ // The site is just suspicious
            // Add to the list with a level of 1
            checked_urls.push({"url" : msg.url, "level": 1});
            while (checked_urls.length>checked_urls_max_length){
                checked_urls.shift();
            }

            createAlertNotification(msg.url, virustotal_res.score, google_res.safe, 1);
            known_unsafe_urls.push(msg.url);
            while(known_unsafe_urls.length>known_unsafe_urls_max_length){
                known_unsafe_urls.shift();
            }
            
            // Set a badge on the extension icon
            try {
                chrome.action.setBadgeText({ text: "!" });
                chrome.action.setBadgeBackgroundColor({ color: "#FF7F00" });
            } catch (e) {
                // setBadgeText may fail in some contexts; ignore
                console.warn("Badge set failed:", e);
            }
        } else { // The site is safe, setting the badge to a green V
            try {
            // Add to the list with a level of 0
            checked_urls.push({"url" : msg.url, "level": 0});
            while (checked_urls.length>checked_urls_max_length){
                checked_urls.shift();
            }

                chrome.action.setBadgeText({ text: "√" });
                chrome.action.setBadgeBackgroundColor({ color: "#00FF00" });
            } catch (e) {
                console.warn("Badge set failed:", e);
            }
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
    return checked_urls.some(item => item.url === url);
}

// Sends a notification that the site is unsafe
function createAlertNotification(url, score, googleStatus, risk_level) {
    const title = (risk_level==1) ? "The Site You Just Entered is Suspicious" : "The Site You Just Entered is Unsafe";
    const google_safe = googleStatus ? "Safe" : "Not Safe";
    const message = `URL: ${url}\nVirusTotal score: ${score}\nGoogle: ${google_safe}`;

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