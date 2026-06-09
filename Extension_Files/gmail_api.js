export async function getAuthToken() {

    return new Promise(
        (resolve, reject) => {

            chrome.identity.getAuthToken(
                {
                    interactive: true
                },
                token => {

                    if (
                        chrome.runtime.lastError
                    ) {
                        reject(
                            chrome.runtime.lastError
                        );
                        return;
                    }

                    resolve(token);
                }
            );
        }
    );
}

export async function listMessages(
    token,
    maxResults = 10
) {

    const response = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${maxResults}`,
        {
            headers: {
                Authorization:
                    `Bearer ${token}`
            }
        }
    );

    return await response.json();
}

export async function getMessage(
    token,
    messageId
) {

    const response = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`,
        {
            headers: {
                Authorization:
                    `Bearer ${token}`
            }
        }
    );

    return await response.json();
}

export async function getRawMessage(
    token,
    messageId
) {

    const response = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=raw`,
        {
            headers: {
                Authorization:
                    `Bearer ${token}`
            }
        }
    );

    return await response.json();
}

export function extractHeaders(
    gmailMessage
) {

    const headers = {};

    const messageHeaders =
        gmailMessage.payload?.headers || [];

    for (
        const header
        of messageHeaders
    ) {

        headers[
            header.name
        ] = header.value;
    }

    return headers;
}

export function convertGmailMessageToEmailData(
    gmailMessage
) {

    const headers =
        extractHeaders(
            gmailMessage
        );

    let body = '';

    try {

        if (
            gmailMessage.payload?.body?.data
        ) {

            body = atob(
                gmailMessage
                    .payload
                    .body
                    .data
                    .replace(/-/g, '+')
                    .replace(/_/g, '/')
            );

        }

    } catch (e) {
        console.warn(
            '[gmail_api] Failed to decode body'
        );
    }

    return {

        subject:
            headers.Subject || '',

        sender:
            headers.From || '',

        receiver:
            headers.To || '',

        body:
            body,

        headers:
            headers,

        urls:
            [],

        source:
            'gmail_api'
    };
}

export async function testGmailAuth() {

    try {

        const token =
            await getAuthToken();

        const messages =
            await listMessages(
                token,
                1
            );

        return {
            success: true,
            token: token,
            messages_found:
                messages.messages
                    ? messages.messages.length
                    : 0
        };

    } catch (e) {

        return {
            success: false,
            error: e.message
        };
    }
}