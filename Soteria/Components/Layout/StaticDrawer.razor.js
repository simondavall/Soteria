const closedClass = "static-drawer--closed";
const layoutClosedClass = "soteria-static-layout--drawer-closed";

function initialiseStaticDrawer() {
    const layout = document.querySelector("[data-static-layout]");
    const drawer = document.querySelector("[data-static-drawer]");
    const toggle = document.querySelector("[data-static-drawer-toggle]");

    if (!layout || !drawer || !toggle ||
        layout.dataset.staticDrawerInitialised === "true") {
        return;
    }

    layout.dataset.staticDrawerInitialised = "true";

    function isOpen() {
        return !drawer.classList.contains(closedClass);
    }

    function setOpen(open) {
        drawer.classList.toggle(closedClass, !open);
        layout.classList.toggle(layoutClosedClass, !open);

        drawer.setAttribute("aria-hidden", (!open).toString());
        toggle.setAttribute("aria-expanded", open.toString());
        toggle.setAttribute(
            "aria-label",
            open ? "Close navigation" : "Open navigation");
    }

    toggle.addEventListener("click", () => {
        setOpen(!isOpen());
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && isOpen()) {
            setOpen(false);
            toggle.focus();
        }
    });

    setOpen(true);
}

if (document.readyState === "loading") {
    document.addEventListener(
        "DOMContentLoaded",
        initialiseStaticDrawer,
        { once: true });
}
else {
    initialiseStaticDrawer();
}

document.addEventListener("enhancedload", initialiseStaticDrawer);