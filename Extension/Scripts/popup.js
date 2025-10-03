// Gets the open tab url:
document.addEventListener("DOMContentLoaded", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const url = tabs[0].url;
        console.log(url);

        if(url.startsWith("http")){
            // Recives the result
            chrome.runtime.sendMessage({ action: "getResult", url:url}, response => {
                if(response!=undefined){
                    console.log("defined");
                    displayResult(response);
                } else {
                    // If the result is from a previus url
                    chrome.runtime.sendMessage({ action: "checkPhish", url: url}, result => {
                        displayResult(result);
                    });
                }
            });
        }
    });
})

// Displays the result in the extension text:
function displayResult(result) {
    let google_safe = result.google === true ? "Safe" : "Not Safe";

    let text = `
        <strong>URL:</strong><br>${result.url}<br>
        <strong>Phish result:</strong><br>
        Google: ${google_safe}<br>
        VirusTotal score: ${result.virustotal}<br>
        Error: ${result.error}
    `;

    document.getElementById("main_text_extension").innerHTML = text;
}