export async function callReferenceApi() {
    const response = await fetch("/internal/reference-api", {
        method: "GET",
        credentials: "same-origin",
        headers: {
            "Accept": "application/json"
        }
    });

    let message = null;

    try {
        const body = await response.json();
        message = body.message ?? null;
    } catch {
        message = null;
    }

    return {
        ok: response.ok,
        status: response.status,
        message
    };
}