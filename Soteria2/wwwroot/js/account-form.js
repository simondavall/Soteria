(() => {
    const fieldSelector = "[data-validation-field]";
    const inputSelector = `${fieldSelector} input, ${fieldSelector} textarea`;

    function clearFieldValidation(input) {
        if (!input.value) {
            return;
        }

        const field = input.closest(fieldSelector);

        if (!field) {
            return;
        }

        field.querySelectorAll(".validation-message").forEach(message => {
            message.textContent = "";
            message.hidden = true;
        });

        input.classList.remove("invalid");
    }

    function handleFieldChange(event) {
        const input = event.target;

        if (!(input instanceof HTMLInputElement) &&
            !(input instanceof HTMLTextAreaElement)) {
            return;
        }

        if (!input.matches(inputSelector)) {
            return;
        }

        clearFieldValidation(input);
    }

    function clearAutofilledFieldValidation() {
        document.querySelectorAll(inputSelector)
            .forEach(clearFieldValidation);
    }

    function checkForDelayedAutofill() {
        clearAutofilledFieldValidation();

        // Some password managers populate fields shortly after page load
        // without consistently raising input or change events.
        const delays = [100, 300, 750, 1500];

        delays.forEach(delay => {
            window.setTimeout(clearAutofilledFieldValidation, delay);
        });
    }

    document.addEventListener("input", handleFieldChange, true);
    document.addEventListener("change", handleFieldChange, true);

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            checkForDelayedAutofill,
            { once: true });
    } else {
        checkForDelayedAutofill();
    }

    window.addEventListener("pageshow", checkForDelayedAutofill);

    if (window.Blazor) {
        Blazor.addEventListener(
            "enhancedload",
            checkForDelayedAutofill);
    }
})();