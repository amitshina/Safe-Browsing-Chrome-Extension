chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentUrl = tabs[0].url;
    console.log(tabs[1])
    const mainText = document.getElementById("main_text_extension");
    if (mainText) {
        mainText.textContent = currentUrl;
    }
});

console.log(currentUrl)