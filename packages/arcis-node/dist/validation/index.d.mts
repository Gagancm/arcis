import { RequestHandler } from 'express';
import { n as ValidationSchema } from '../types-D7WNLpcY.mjs';

/**
 * @module @arcis/node/validation/schema
 * Request validation middleware
 */

/**
 * Create Express middleware for request validation.
 * Prevents mass assignment by only allowing fields defined in the schema.
 *
 * @param schema - Validation schema defining expected fields
 * @param source - Request property to validate ('body', 'query', or 'params')
 * @returns Express middleware
 *
 * @example
 * app.post('/users', validate({
 *   email: { type: 'email', required: true },
 *   name: { type: 'string', min: 2, max: 50 },
 *   age: { type: 'number', min: 0, max: 150 },
 *   role: { type: 'string', enum: ['user', 'admin'] }
 * }), handler);
 *
 * @example
 * // Validate query params
 * app.get('/search', validate({
 *   q: { type: 'string', required: true, min: 1 },
 *   page: { type: 'number', min: 1 }
 * }, 'query'), handler);
 */
declare function validate(schema: ValidationSchema, source?: 'body' | 'query' | 'params'): RequestHandler;
/**
 * Alias for validate
 * @see validate
 */
declare const createValidator: typeof validate;

export { createValidator, validate };
