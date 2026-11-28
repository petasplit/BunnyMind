import { describe, test, expect } from "bun:test";
import { inspect } from "./bunnymind_ast.mjs";

describe("BunnyMind TypeScript AST/static JavaScript analysis", () => {
 test("finds legitimate fetch, axios, XHR and URL references without executing code", () => {
  const js = [
   "fetch('/api/profile?token=SECRET');",
   "axios.post('/api/order', {body:'value'});",
   "const xhr = new XMLHttpRequest(); xhr.open('GET','/api/items');",
   "const route = new URL('/api/v2/view', location.href);",
   "window.endpoint = '/api/ignored';",
   "fetch('https://outside.test/private');",
   "fetch('/logout');",
   "fetch('/api/' + userInput);",
  ].join("\n");
  const report=inspect(js,"https://app.example");
  const rows=report.endpoints.map(e=>e.method+"|"+e.path);
  for(const expected of ["GET|/api/profile","POST|/api/order","GET|/api/items","GET|/api/v2/view"]){
   expect(rows).toContain(expected);
  }
  expect(JSON.stringify(report)).not.toContain("SECRET");
  expect(rows.some(x=>x.includes("outside")||x.includes("logout"))).toBe(false);
  expect(report.parse_errors.length).toBe(0);
 });
 test("maps AST site to original location with ECMA-426 VLQ segments", () => {
  const map=JSON.stringify({version:3,sources:["src/router.ts"],names:[],
    mappings:"AAAA",sourcesContent:["SECRET_PRIVATE_VALUE"]});
  const result=inspect("fetch('/api/test')","https://app.example",map);
  expect(result.endpoints[0].original.source_name).toBe("router.ts");
  expect(result.endpoints[0].original.line).toBe(1);
  expect(result.source_map.status).toBe("verified_map_metadata");
  expect(JSON.stringify(result)).not.toContain("SECRET_PRIVATE_VALUE");
 });
 test("malformed source maps cannot be interpreted as valid provenance", () => {
  const result=inspect("fetch('/api/test')","https://app.example",
    JSON.stringify({version:3,sources:["source.js"],mappings:"%%%"}));
  expect(result.source_map.status).toBe("invalid_map");
 });
 test("rejects scope escape and oversized input without fetching", () => {
  expect(()=>inspect("fetch('/api')","http://app.example")).toThrow();
  expect(()=>inspect("fetch('/api')","https://app.example/user")).toThrow();
  expect(()=>inspect("X".repeat(513*1024),"https://app.example")).toThrow();
 });
});
