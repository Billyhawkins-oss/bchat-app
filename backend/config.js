import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';

function getEnv(name) {
  const value = process.env[name];
  return typeof value === 'string' ? value.trim() : '';
}

function parseOrigins(value) {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

const requiredEnvVars = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter((name) => !getEnv(name));

export const config = {
  port: Number(process.env.PORT || 3000),
  jwtSecret: getEnv('JWT_SECRET'),
  supabaseUrl: getEnv('SUPABASE_URL'),
  supabaseServiceRoleKey: getEnv('SUPABASE_SERVICE_ROLE_KEY'),
  adminUsername: getEnv('ADMIN_USERNAME') || 'admin821',
  adminPassword: getEnv('ADMIN_PASSWORD'),
  allowedOrigins: parseOrigins(getEnv('ALLOWED_ORIGINS') || 'http://localhost:3000,http://127.0.0.1:3000'),
  frontendOrigin: getEnv('FRONTEND_ORIGIN') || ''
};

export function assertRequiredEnv() {
  if (missingEnvVars.length) {
    throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  }
}

export const supabase = config.supabaseUrl && config.supabaseServiceRoleKey
  ? createClient(config.supabaseUrl, config.supabaseServiceRoleKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false
      }
    })
  : null;
