// Gets the open tab url:

// Recives the result and updates the extension
document.addEventListener("DOMContentLoaded", () => {
    chrome.runtime.sendMessage({ action: "getResult" }, response => {
        if (!response) {
            document.getElementById("main_text_extension").innerText = "404";
            //chrome.runtime.sendMessage({action: "checkPhish", url: window.location.href});
            return;
        }

        let google_safety = response.google === true ? "Safe" : "Not Safe";

        let result = `
        <strong>URL:</strong><br>
        ${response.url}<br>
        <strong>Phish result:</strong><br>
        Google: ${google_safety}<br>
        VirusTotal score: ${response.virustotal}<br>
        Error: ${response.error}
        `;

        document.getElementById("main_text_extension").innerHTML = result;
    });
});
