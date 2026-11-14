/**
 * The fixture adapter's allowed origin. The port is a placeholder: the suite's global setup
 * (test/global-setup.ts) copies the registry for each run and writes this file with a port the
 * operating system chose. Test code reads the port through `fixturePort()` in
 * ../run-context.ts instead of importing this file.
 */
export const FIXTURE_ORIGIN = 'http://127.0.0.1:0';
