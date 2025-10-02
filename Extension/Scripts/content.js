// Automaticly checks the url
chrome.runtime.sendMessage({action: "checkPhish", url: window.location.href});
