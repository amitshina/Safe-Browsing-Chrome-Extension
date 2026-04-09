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


function shortenUrl(url, maxLength = 80) {
    return url.length > maxLength
        ? url.slice(0, maxLength) + "…"
        : url;
}

// Updates the circle color:
function setScoreState(state) {
    const scoreCircle = document.getElementById("score-circle");
    scoreCircle.classList.remove("safe", "warning", "unsafe");

    // Debug:
    console.log(scoreCircle.className);

    // Add the new one
    scoreCircle.classList.add(state);
}


// Displays the result in the extension text:
function displayResult(result) {
    let google_safe = result.google === true ? "Safe" : "Not Safe";
    // google_safe += `<br> - results form Google API`

    let text = `
        <strong>URL:</strong><br>${result.url}<br>
        Google: ${google_safe}<br>
        VirusTotal score: ${result.virustotal}<br>
        Error: ${result.error} 
    `; // The error field is for debugging

    console.log(text);
    document.getElementById("url-text").innerHTML = shortenUrl(result.url);;

    // Update the Url Score text and label with the scores
    if(result.google==false && result.virustotal_num_score<result.unsafe_site_score){ // google flags as unsafe while virustotal doesn't
        document.getElementById("score-text").innerHTML = google_safe; 
        document.getElementById("score-label").innerHTML = "Google API";
    }
    else if(result.virustotal==null || result.virustotal==undefined){
        //use google score if is defined:
        if(result.google==undefined || result.google==null){
            //no results
            document.getElementById("score-text").innerHTML = "Unknown";
            document.getElementById("score-label").innerHTML = "No Results"
            
        }
        //google results
        document.getElementById("score-text").innerHTML = google_safe;
        document.getElementById("score-label").innerHTML = "Google API";
    }
    else{
        // Use VirusTotal results
        console.log(result.v_score);
        document.getElementById("score-text").innerHTML = result.virustotal;
        document.getElementById("score-label").innerHTML = "Virustotal API";
        if(result.v_score == 2){
            setScoreState("unsafe");
            document.getElementById("status-text").innerHTML = "The Site is Probably Unsafe";
        }
        else if(result.v_score==1){
            setScoreState("warning");
            document.getElementById("status-text").innerHTML = "The Site is Suspicius";
        }
        else if(result.v_score==0){
            setScoreState("safe");
            document.getElementById("status-text").innerHTML = "This Site is Probably Safe";
        }   
    }
}
