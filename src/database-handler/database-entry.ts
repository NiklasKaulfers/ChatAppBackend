import * as ddb from "@aws-sdk/lib-dynamodb"
import {DynamoDBClient} from "@aws-sdk/client-dynamodb";


export default class DatabaseHandler {
    private readonly documentClient: ddb.DynamoDBDocumentClient;

    constructor() {
        const client: DynamoDBClient = new DynamoDBClient()
        this.documentClient = ddb.DynamoDBDocumentClient.from(client)
    }

    async sendPutCommand(input: ddb.PutCommandInput){
        try {
            return await this.documentClient.send(new ddb.PutCommand(input))
        } catch(err) {
            throw err;
        }
    }

    async sendGetCommand(input: ddb.GetCommandInput){
        try {
            return await this.documentClient.send(new ddb.GetCommand(input))
        } catch(err) {
            throw err;
        }
    }

}