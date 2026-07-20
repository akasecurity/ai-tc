// Stub for `react-devtools-core`. ink imports it from build/devtools.js, but only
// reaches that module when DEV mode is on AND the package resolves — neither is true
// for the CLI. With splitting disabled the single-file bundle hoists ink's static
// `import 'react-devtools-core'`, so it must resolve to *something*; this no-op stands
// in for a package we never install and whose code never executes at runtime.
export default {
  initialize() {},
  connectToDevTools() {},
};
