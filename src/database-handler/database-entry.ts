import pg from "pg"
import {checkValidCharsForDB} from "../security/check-valid-chars-for-db";

interface DatabaseEntryProps {
    values: {
        key: string,
        value: any
    }[]
}


export default class DatabaseHandler {
    private readonly pool: pg.Pool;

    constructor(databaseUrl: string) {
        this.pool = new pg.Pool({
            connectionString: databaseUrl,
            ssl: {rejectUnauthorized: false},
        })
    }

    async databaseEntry(props: DatabaseEntryProps) {
        props.values.map((value) => {
            const validity: boolean = checkValidCharsForDB(value.value);
            if (!validity) throw new Error("Invalid syntax in " + value.key)
        })

        const valueNamesStringified =
            "("
            + props.values.map((pair) => {
                return pair.value
            }).toString()
            + ")"
        // todo: implement regex and valid db entries -> verify with actual db


        throw new Error("Not implemented yet")
        // await this.pool.query("NOT IMPLEMENTED YET")

    }

}