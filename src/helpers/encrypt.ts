/**
 * Encodes an object into Base64 URL format
 * @param {*} authorization - an object with the required authorization properties
 **/
function getBase64URLEncoded(authorization: string): string {
    return btoa(JSON.stringify(authorization))
        .replace(/\+/g, '-') // Convert '+' to '-'
        .replace(/\//g, '_') // Convert '/' to '_'
        .replace(/=+$/, '') // Remove padding `=`
}

export function getAuthProtocol(authorization: string): string {
    const header = getBase64URLEncoded(authorization)
    return `header-${header}`
}