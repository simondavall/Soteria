(() => {
    const fieldSelector = "[data-validation-field]";
    const inputSelector = `${fieldSelector} input, ${fieldSelector} textarea`;

    const knownValues = new WeakMap();

    function getInputs() {
        return document.querySelectorAll(inputSelector);
    }

    function rememberCurrentValues() {
        getInputs().forEach(input => {
            knownValues.set(input, input.value);
        });
    }

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
        knownValues.set(input, input.value);
    }

    function clearChangedAutofilledFields() {
        getInputs().forEach(input => {
            const knownValue = knownValues.get(input);

            if (knownValue === undefined) {
                knownValues.set(input, input.value);
                return;
            }

            if (input.value === knownValue) {
                return;
            }

            clearFieldValidation(input);
            knownValues.set(input, input.value);
        });
    }

    function initialisePage() {
        rememberCurrentValues();

        // Some password managers populate fields shortly after page load
        // without consistently raising input or change events.
        const delays = [100, 300, 750, 1500];

        delays.forEach(delay => {
            window.setTimeout(clearChangedAutofilledFields, delay);
        });
    }

    document.addEventListener("input", handleFieldChange, true);
    document.addEventListener("change", handleFieldChange, true);

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            initialisePage,
            { once: true });
    } else {
        initialisePage();
    }

    window.addEventListener("pageshow", initialisePage);

    if (window.Blazor) {
        Blazor.addEventListener(
            "enhancedload",
            initialisePage);
    }
})();