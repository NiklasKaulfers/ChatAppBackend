export function checkValidCharsForDB(input: string):boolean {
    return !(input.includes("}")
        || input.includes("{")
        || input.includes(";")
        || input.includes(",")
        || input.includes("'")
        || input.includes('"'));
}