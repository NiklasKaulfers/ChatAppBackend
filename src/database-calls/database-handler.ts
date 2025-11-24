import {DatabaseError} from "../error/database-error";
import {createClient, SupabaseClient} from "@supabase/supabase-js";
import {User} from "../objects/user";
import {ValidationError} from "../error/validation-error";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;

export class DatabaseHandler {
    supabase: SupabaseClient;
    constructor() {
        if (!SUPABASE_KEY || !SUPABASE_URL) {
            console.error("Supabase info missing.")
            throw new DatabaseError("Supabase info missing.", 500);
        }

        this.supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);
    }

    async checkLogs(): Promise<any> {
        const { data, error } = await this.supabase
            .from("logs")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(100);
        if (error) throw new DatabaseError(error.message, 500);
        return data;
    }

    async getUser(userId: string): Promise<any> {
        const {data, error} = await this.supabase
            .from("users")
            .select("id, email")
            .eq("id", userId)
            .limit(1);

        if (error) {
            throw new DatabaseError(error.message, 500);
        }

        if (!data || data.length === 0) {
            throw new ValidationError("User not found", 403)
        }
        return data;
    }
}
