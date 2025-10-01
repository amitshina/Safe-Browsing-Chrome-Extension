// from a content script or popup:
chrome.runtime.sendMessage(
    { action: "checkPhish", url: "https://app.clientepessoafisica.click"},
    response => {
        if (!response) {
        console.error("No response - maybe the service worker is inactive or crashed.");
        return;
        }
        console.log("Phish result:", response);
    }
);
