// Automaticly checks the url
const this_url = window.location.href;
chrome.runtime.sendMessage({action: "isCheckedUrl", url: this_url}, response =>{
    console.log(response);
    // Calls the check function if it hasn'nt been checked recently
    if(!response){
        chrome.runtime.sendMessage({action: "checkPhish", url: this_url});
    }
});