// Condition expressions for aws dynamodb
// avoid hardcoded strings as much as possible

export function attributeNotExists(value: string): string {
    return "attribute_not_exists(" + value + ")";
}

export function attributeExists(value: string): string {
    return "attribute_exists(" + value + ")";
}