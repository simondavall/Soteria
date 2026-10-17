const closedClass = "static-drawer--closed";
const openClass = "static-drawer--open";
const layoutClosedClass = "soteria-static-layout--drawer-closed";
const layoutOpenClass = "soteria-static-layout--drawer-open";

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
        if (drawer.classList.contains(openClass)) {
            return true;
        }

        if (drawer.classList.contains(closedClass)) {
            return false;
        }

        return window.matchMedia("(min-width: 960px)").matches;
    }

    function setOpen(open) {
        drawer.classList.toggle(openClass, open);
        drawer.classList.toggle(closedClass, !open);

        layout.classList.toggle(layoutOpenClass, open);
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

    setOpen(isOpen());
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