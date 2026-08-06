import { assertRequiredEnv } from '../config.js';

try {
  assertRequiredEnv();
  console.log('Environment validation passed.');
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
