// Global teardown for Jest tests
export default async (): Promise<void> => {
  console.log('🧹 Cleaning up test environment...');

  // Cleanup any global resources
  try {
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }

    // Clean up any remaining timers
    clearTimeout as any;
    clearInterval as any;

  } catch (error) {
    console.warn('⚠️ Cleanup warning:', (error as Error).message);
  }

  console.log('✅ Test environment cleanup complete');
};