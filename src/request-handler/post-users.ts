import bcrypt from "bcryptjs";
import {Response} from "express";
import DatabaseHandler from "../database-handler/database-entry";
import {DATABASE_NAMING} from "../database-handler/database-naming-definitions";


interface PostUserProps {
    body: any;
    res: Response;
    databaseHandler: DatabaseHandler
}

export async function postUsers(props: PostUserProps): Promise<Response> {
    const userData: PostUsersRequiredInput = validateBody(props.body);
    try {
        const hashedPassword = await bcrypt.hash(userData.password, 10);
        await props.databaseHandler.databaseEntry({
                values: [
                    {
                        value: userData.userName,
                        key: DATABASE_NAMING.USER_TABLE.USERNAME
                    }, {
                        value: hashedPassword,
                        key: DATABASE_NAMING.USER_TABLE.PASSWORD
                    }, {
                        value: userData.email,
                        key: DATABASE_NAMING.USER_TABLE.EMAIL
                    }
                ]
            }
        )
        props.res.status(201).json({message: `User ${userData.userName} has been created.`});
    } catch (err) {
        console.error(err);
        props.res.status(500).json({error: "Database error occurred."});
    }
    return props.res;
}

interface PostUsersRequiredInput {
    email: string,
    userName: string,
    password: string
}

function validateBody(body: any): PostUsersRequiredInput {
    const input: PostUsersRequiredInput = body;

    if (!input.userName && !input.email && !input.password) throw new Error("No parameters passed")

    if (!input.userName) throw new Error("Undefined user")
    if (!input.email) throw new Error("Undefined email")
    if (!input.password) throw new Error("Undefined password")

    return input;
}