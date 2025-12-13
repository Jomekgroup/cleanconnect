// FIX: Removed triple-slash directive to resolve "Cannot find type definition file for 'vite/client'" error in certain environments.
// The interfaces below provide the necessary types for `import.meta.env`.
interface ImportMetaEnv {
  readonly VITE_API_URL: string;
  // more env variables...
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}