/* Test harness only; mirrors the workspace's dependency-free Node declarations. */
declare module 'node:http' { export function createServer(...args: any[]): any; export function request(...args: any[]): any; }
declare module 'node:https' { export function createServer(...args: any[]): any; export function request(...args: any[]): any; }
declare module 'node:process' { const process: any; export default process; }
