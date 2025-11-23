export interface IRoom {
    id: string;
    displayName: string;
    creator: string;
    pin: string;

}

export class Room {
    id: string;
    displayName: string;
    creator: string;
    pin: string;

    constructor(private readonly room: IRoom) {
        this.id = room.id;
        this.displayName = room.displayName;
        this.creator = room.creator;
        this.pin = room.pin;
    }

    toDto() {
        return {
            id: this.id,
            display_name: this.displayName,
            creator: this.creator,
            pin: this.pin,
        }
    }

}