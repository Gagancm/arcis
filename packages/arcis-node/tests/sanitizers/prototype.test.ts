/**
 * Prototype Pollution Sanitizer Tests
 * Tests for src/sanitizers/prototype.ts
 */

import { describe, it, expect } from 'vitest';
import { isDangerousProtoKey, detectPrototypePollution, getDangerousProtoKeys } from '../../src/sanitizers/prototype';

describe('isDangerousProtoKey', () => {
  describe('Dangerous Keys', () => {
    it('should detect __proto__', () => {
      expect(isDangerousProtoKey('__proto__')).toBe(true);
    });

    it('should detect constructor', () => {
      expect(isDangerousProtoKey('constructor')).toBe(true);
    });

    it('should detect prototype', () => {
      expect(isDangerousProtoKey('prototype')).toBe(true);
    });
  });

  describe('Case-Insensitive Detection', () => {
    it('should detect __PROTO__', () => {
      expect(isDangerousProtoKey('__PROTO__')).toBe(true);
    });

    it('should detect Constructor', () => {
      expect(isDangerousProtoKey('Constructor')).toBe(true);
    });

    it('should detect PROTOTYPE', () => {
      expect(isDangerousProtoKey('PROTOTYPE')).toBe(true);
    });

    it('should detect __Proto__', () => {
      expect(isDangerousProtoKey('__Proto__')).toBe(true);
    });

    it('should detect __DEFINEGETTER__', () => {
      expect(isDangerousProtoKey('__DEFINEGETTER__')).toBe(true);
    });
  });

  describe('Legacy Prototype Methods', () => {
    it('should detect __defineGetter__', () => {
      expect(isDangerousProtoKey('__defineGetter__')).toBe(true);
    });

    it('should detect __defineSetter__', () => {
      expect(isDangerousProtoKey('__defineSetter__')).toBe(true);
    });

    it('should detect __lookupGetter__', () => {
      expect(isDangerousProtoKey('__lookupGetter__')).toBe(true);
    });

    it('should detect __lookupSetter__', () => {
      expect(isDangerousProtoKey('__lookupSetter__')).toBe(true);
    });
  });

  describe('Safe Keys', () => {
    it('should allow normal field names', () => {
      expect(isDangerousProtoKey('name')).toBe(false);
    });

    it('should allow _id', () => {
      expect(isDangerousProtoKey('_id')).toBe(false);
    });

    it('should allow numeric keys', () => {
      expect(isDangerousProtoKey('0')).toBe(false);
    });

    it('should allow keys containing proto but not exactly __proto__', () => {
      expect(isDangerousProtoKey('proto')).toBe(false);
      expect(isDangerousProtoKey('myPrototype')).toBe(false);
    });

    it('should allow keys containing constructor as substring', () => {
      expect(isDangerousProtoKey('myConstructor')).toBe(false);
    });
  });
});

describe('detectPrototypePollution', () => {
  // Note: In JavaScript, { __proto__: {} } as an object literal sets the prototype,
  // it doesn't create a key called "__proto__". Use JSON.parse to create literal keys.
  
  describe('Top-Level Detection', () => {
    it('should detect __proto__ at top level (via JSON.parse)', () => {
      // JSON.parse creates actual __proto__ key, unlike object literals
      const obj = JSON.parse('{"__proto__": {"admin": true}}');
      expect(detectPrototypePollution(obj)).toBe(true);
    });

    it('should detect constructor at top level', () => {
      expect(detectPrototypePollution({ constructor: { prototype: {} } })).toBe(true);
    });

    it('should detect prototype at top level', () => {
      expect(detectPrototypePollution({ prototype: { isAdmin: true } })).toBe(true);
    });
  });

  describe('Nested Object Detection', () => {
    it('should detect __proto__ in nested objects (via JSON.parse)', () => {
      const obj = JSON.parse('{"user": {"__proto__": {"admin": true}}}');
      expect(detectPrototypePollution(obj)).toBe(true);
    });

    it('should detect constructor in nested objects', () => {
      expect(detectPrototypePollution({ 
        config: { 
          settings: { 
            constructor: {} 
          } 
        } 
      })).toBe(true);
    });

    it('should detect deeply nested pollution (via JSON.parse)', () => {
      const obj = JSON.parse('{"a": {"b": {"c": {"d": {"__proto__": {}}}}}}');
      expect(detectPrototypePollution(obj)).toBe(true);
    });
  });

  describe('Array Detection', () => {
    it('should detect pollution in arrays (via JSON.parse)', () => {
      const obj = JSON.parse('[{"__proto__": {}}]');
      expect(detectPrototypePollution(obj)).toBe(true);
    });

    it('should detect pollution in nested arrays (via JSON.parse)', () => {
      const obj = JSON.parse('{"items": [{"config": {"__proto__": {}}}]}');
      expect(detectPrototypePollution(obj)).toBe(true);
    });
  });

  describe('Case-Insensitive Detection', () => {
    it('should detect __PROTO__ (via JSON.parse)', () => {
      const obj = JSON.parse('{"__PROTO__": {"admin": true}}');
      expect(detectPrototypePollution(obj)).toBe(true);
    });

    it('should detect Constructor', () => {
      expect(detectPrototypePollution({ Constructor: { prototype: {} } })).toBe(true);
    });

    it('should detect PROTOTYPE', () => {
      expect(detectPrototypePollution({ PROTOTYPE: {} })).toBe(true);
    });
  });

  describe('Legacy Prototype Methods', () => {
    it('should detect __defineGetter__', () => {
      expect(detectPrototypePollution({ __defineGetter__: {} })).toBe(true);
    });

    it('should detect __defineSetter__', () => {
      expect(detectPrototypePollution({ __defineSetter__: {} })).toBe(true);
    });

    it('should detect __lookupGetter__', () => {
      expect(detectPrototypePollution({ __lookupGetter__: {} })).toBe(true);
    });

    it('should detect nested __defineGetter__', () => {
      expect(detectPrototypePollution({ a: { __defineGetter__: {} } })).toBe(true);
    });
  });

  describe('Safe Objects', () => {
    it('should return false for safe objects', () => {
      expect(detectPrototypePollution({ name: 'John', age: 30 })).toBe(false);
    });

    it('should return false for null', () => {
      expect(detectPrototypePollution(null)).toBe(false);
    });

    it('should return false for primitives', () => {
      expect(detectPrototypePollution('string')).toBe(false);
      expect(detectPrototypePollution(123)).toBe(false);
      expect(detectPrototypePollution(true)).toBe(false);
    });

    it('should return false for empty objects', () => {
      expect(detectPrototypePollution({})).toBe(false);
    });

    it('should return false for arrays without pollution', () => {
      expect(detectPrototypePollution([1, 2, 3])).toBe(false);
    });
  });

  describe('Max Depth Protection', () => {
    it('should respect max depth limit', () => {
      const deepObject = JSON.parse('{"a": {"b": {"c": {"__proto__": {}}}}}');
      // With maxDepth of 2, should not detect at depth 3+
      expect(detectPrototypePollution(deepObject, 2)).toBe(false);
    });

    it('should detect within max depth (via JSON.parse)', () => {
      const deepObject = JSON.parse('{"a": {"__proto__": {}}}');
      expect(detectPrototypePollution(deepObject, 3)).toBe(true);
    });
  });
});

describe('getDangerousProtoKeys', () => {
  it('should return an array', () => {
    const keys = getDangerousProtoKeys();
    expect(Array.isArray(keys)).toBe(true);
  });

  it('should include __proto__', () => {
    const keys = getDangerousProtoKeys();
    expect(keys).toContain('__proto__');
  });

  it('should include constructor', () => {
    const keys = getDangerousProtoKeys();
    expect(keys).toContain('constructor');
  });

  it('should include prototype', () => {
    const keys = getDangerousProtoKeys();
    expect(keys).toContain('prototype');
  });

  it('should include __definegetter__', () => {
    const keys = getDangerousProtoKeys();
    expect(keys).toContain('__definegetter__');
  });

  it('should include __definesetter__', () => {
    const keys = getDangerousProtoKeys();
    expect(keys).toContain('__definesetter__');
  });

  it('should include __lookupgetter__', () => {
    const keys = getDangerousProtoKeys();
    expect(keys).toContain('__lookupgetter__');
  });

  it('should include __lookupsetter__', () => {
    const keys = getDangerousProtoKeys();
    expect(keys).toContain('__lookupsetter__');
  });
});
