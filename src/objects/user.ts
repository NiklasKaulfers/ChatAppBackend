interface UserProps {
    email: string;
    password: string;
    username: string;
}

export class User {
    email: string;
    password: string;
    username: string;

    constructor(props: UserProps) {
        this.email = props.email;
        this.password = props.password;
        this.username = props.username;
    }

    toDto() {
        return {
            email: this.email,
            password: this.password,
            username: this.username,
        }
    }
}