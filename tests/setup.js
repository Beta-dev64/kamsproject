"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.testConfig = void 0;
// Set test environment
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce log noise during tests
// Mock console methods for cleaner test output
global.console = {
    ...console,
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
};
// Set test timeout
jest.setTimeout(30000);
// Global test setup
beforeAll(async () => {
    // Add any global setup here
});
afterAll(async () => {
    // Add any global cleanup here
});
// Add any global test utilities here
exports.testConfig = {
    dbUrl: 'postgresql://test:test@localhost:5432/kam_test',
    jwtSecret: 'test-jwt-secret',
};
//# sourceMappingURL=setup.js.map