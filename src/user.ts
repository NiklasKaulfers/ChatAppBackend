interface UserProps {
    userName: string,
    password: string,
    email: string
}

export default class User {
    private readonly userName: string;
    private readonly email: string;
    private readonly password: string;


    constructor(props: UserProps) {
        this.userName = props.userName;
        this.password = props.password;
        this.email = this.validEmail(props.email);
    }


    private validEmail(uncheckedEmail: string): string{
        return this.email
    }

    dto(){
        return {
            userName: this.userName,
            password: this.password,
            email: this.email,
        }
    }

    getUserName(){
        return this.userName;
    }

    getEmail(){
        return this.email;
    }
}