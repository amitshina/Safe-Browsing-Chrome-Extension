// Recives the result and updates the extension
document.addEventListener("DOMContentLoaded", () => {
    chrome.runtime.sendMessage({ action: "getResult" }, response => {
        if (!response) {
            document.getElementById("main_text_extension").innerText = "404";
            return;
        }

        let google_safety = "";
        if (response.google) {
            google_safety = "Safe";
        }
        else{
            google_safety = "Not Safe";
        }

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
