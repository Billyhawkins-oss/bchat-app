import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

function fail(message) {
  console.error('Migration failed:', message);
  process.exit(1);
}

if (!supabaseUrl || !supabaseKey) {
  fail('Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your environment.');
}

const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false
  }
});

async function migrate() {
  console.log('Supabase migration entrypoint is available for future data import workflows.');
  console.log('No local SQLite data is imported by this production build.');
}

migrate().catch((error) => {
  console.error('Migration error:', error.message || error);
  process.exit(1);
});
