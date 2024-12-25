/**
 * allows to create Rooms and who has access to the rooms
 */
export class roomHandling{
    private readonly _roomID: string;
    private readonly _users: Array<string>;
    public constructor(roomID: string, creator: string) {
        this._roomID = roomID;
        this._users = new Array<string>(creator);
    }

    /**
     * adds a single user to the room
     * returns true if user was added successfully and false if not
     * @param userID the user that will join the room
     */
    addUser(userID: string):boolean{
        for (const user in this._users) {
            if (user === userID){
                console.log(`[ERROR] user ${userID} is already in ${this._roomID}`)
                return false;
            }
        }
        this._users.push(userID)
        return true;
    }

    get roomID(): string {
        return this._roomID;
    }
    get users(): Array<string>{
        return this._users
    }
}