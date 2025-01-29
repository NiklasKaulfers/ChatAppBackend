export class Room{
    private readonly _roomId: string;
    private readonly _inRoom: Set<string>;
    constructor(roomId: string) {
        this._roomId = roomId;
        this._inRoom = new Set<string>();
    }

    joinRoom(userId: string): void{
        this._inRoom.add(userId)
    }

    leaveRoom(userId: string): void{
        if (this._inRoom.has(userId)){
            this._inRoom.delete(userId);
        }
    }

    get roomId(): string {
        return this._roomId;
    }

    get inRoom(): Set<string> {
        return this._inRoom;
    }
}

export class ActiveRooms{
    private readonly _activeRooms: Set<Room>;
    constructor() {
        this._activeRooms = new Set<Room>();
    }

    add(room: Room){
        this._activeRooms.add(room);
    }

    remove(roomId: string){
        this._activeRooms.forEach(room => {
            if (room.roomId === roomId){
                this._activeRooms.delete(room);
                return;
            }
        });
    }

    get activeRooms(): Set<Room> {
        return this._activeRooms
    }
}