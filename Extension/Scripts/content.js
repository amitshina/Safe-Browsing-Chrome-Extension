const currentUrl = window.location.href;

const mainText = document.getElementById("main_text_extension");

if (mainText) {
    mainText.textContent = currentUrl;
}

console.log(currentUrl)