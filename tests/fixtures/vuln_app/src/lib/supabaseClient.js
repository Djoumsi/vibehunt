import { createClient } from '@supabase/supabase-js'
// FAUTE : service_role côté client
const SERVICE_ROLE = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.abcdef1234567890XyZserviceRoleKeyExposedHere999"
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, SERVICE_ROLE)
