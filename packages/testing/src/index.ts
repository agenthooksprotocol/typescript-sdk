import { fileURLToPath } from "node:url";

export const fakeBackendEntrypoint = fileURLToPath(new URL("./fake-backend.js", import.meta.url));
