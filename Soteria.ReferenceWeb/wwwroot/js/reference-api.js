export async function callReferenceApi(endpoint) {
    const response = await fetch(
        `/internal/reference-api/${encodeURIComponent(endpoint)}`,
        {
            method: "GET",
            credentials: "same-origin",
            headers: {
                "Accept": "application/json"
            }
        });

    let body = null;

    try {
        body = await response.json();
    } catch {
        body = null;
    }

    return {
        ok: response.ok,
        status: response.status,
        message: body?.message ?? null,
        data: response.ok ? body : null
    };
}