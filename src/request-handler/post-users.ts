import bcrypt from "bcryptjs";
import {Response} from "express";
import DatabaseHandler from "../database-handler/database-entry";
import {attributeNotExists} from "../database-handler/dynamoDb-condition-expression";
import User from "../user";


interface PostUserProps {
    body: any;
    res: Response;
    databaseHandler: DatabaseHandler
}

export async function postUsers(props: PostUserProps): Promise<Response> {
    const user: User = await validateBody(props.body);
    try {
        const dbResponse = await props.databaseHandler.sendPutCommand({
                Item: user.dto(),
                ConditionExpression: attributeNotExists("email"),
                TableName: "we3-user"
            }
        )
        if (dbResponse.$metadata.httpStatusCode == 200) {
            props.res.status(201).json({message: `User ${user.getUserName()} has been created.`});
            return props.res;
        }
        props.res.status(400).json({message: `User already exists for given email: ${user.getEmail()}`});
        return props.res;
    } catch (err) {
        console.error(err);
        return props.res.status(500).json({error: "Database error occurred."});
    }
}

interface PostUsersRequiredInput {
    email: string,
    userName: string,
    password: string
}

async function validateBody(body: any): Promise<User> {
    const input: PostUsersRequiredInput = body;

    if (!input.userName && !input.email && !input.password) throw new Error("No parameters passed")

    if (!input.userName) throw new Error("Undefined user")
    if (!input.email) throw new Error("Undefined email")
    if (!input.password) throw new Error("Undefined password")

    input.password = await bcrypt.hash(input.password, 10);

    return new User(input);
}