// =========================================
// ZERO TRUST SECURITY PIPELINE
// Frontend interactions
// =========================================

document.addEventListener("DOMContentLoaded", function () {

    // Highlight placeholder modules when clicked.
    const placeholderLinks = document.querySelectorAll(".placeholder-link");

    placeholderLinks.forEach(function (link) {
        link.addEventListener("click", function (event) {
            event.preventDefault();

            alert("This module is under development. It will be connected by the team.");
        });
    });

    // Automatically hide flash messages.
    const flashMessages = document.querySelectorAll(".flash-message");

    flashMessages.forEach(function (message) {
        setTimeout(function () {
            message.style.transition = "opacity 0.5s ease";
            message.style.opacity = "0";

            setTimeout(function () {
                message.remove();
            }, 500);

        }, 4000);
    });

});
