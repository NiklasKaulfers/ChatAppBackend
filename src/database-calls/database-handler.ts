import {DatabaseError} from "../error/database-error";
import {createClient, SupabaseClient} from "@supabase/supabase-js";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;

interface SupabaseReturnValues {
    data: any,
    error: any,
}
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
}
