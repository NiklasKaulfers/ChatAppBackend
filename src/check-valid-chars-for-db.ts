export function checkValidCharsForDB(input: string):boolean {
    if (input.includes("}") || input.includes("{") || input.includes(";")
        || input.includes(",") || input.includes("'") || input.includes('"')) {
        return false;
    }
    return true;
}