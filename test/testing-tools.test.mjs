import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { shouldLogApiSecurity } from "../modules/api-security-logging.ts";

function request(path, contentType = "application/json") {
  return {
    url: `https://gateway.example${path}`,
    headers: new Headers(contentType === null ? {} : { "content-type": contentType }),
    // The logging decision must never inspect either secret-bearing body.
    get body() { throw new Error("Request body must not be read"); },
  };
}

test("excludes the unlock endpoint and private subtree before inspecting content type or body", () => {
  for (const path of [
    "/api/testing-tools", "/api/testing-tools/", "/api/testing-tools/unlock",
    "/api/testing-tools/future/nested", "/api/testing-tools/unlock?source=example",
    "/API/Testing-Tools/UnLoCk", "/api/%74esting-tools/unlock",
    "/api%2Ftesting-tools%2funlock", "/api%5ctesting-tools%5cunlock",
    "//api///testing-tools//unlock", "/api/other/../testing-tools/unlock",
    "/api/other%2F..%2Ftesting-tools/unlock",
  ]) {
    const input = request(path);
    input.headers = { get() { throw new Error("Private path must be excluded first"); } };
    assert.equal(shouldLogApiSecurity(input), false, path);
  }
});

test("preserves logging on existing JSON endpoints and similarly named public paths", () => {
  for (const path of [
    "/api/auth/login", "/api/auth/register", "/api/auth/users", "/api/chat",
    "/api/testing-tools-public/unlock", "/api/testing-tools.json",
    "/other/api/testing-tools/unlock", "/api/auth/login?next=/api/testing-tools/unlock",
  ]) {
    assert.equal(shouldLogApiSecurity(request(path)), true, path);
  }
});

test("preserves the existing exact content-type filter for ordinary traffic", () => {
  for (const contentType of [null, "text/plain", "application/json; charset=utf-8", "APPLICATION/JSON"]) {
    assert.equal(shouldLogApiSecurity(request("/api/auth/login", contentType)), false);
  }
});

test("fails closed on invalid URLs and malformed path encoding", () => {
  for (const url of [
    "not a URL", "https://[invalid", "https://gateway.example/api/%",
    "https://gateway.example/api/%ZZ", "https://gateway.example/api/%E0%A4%A",
    "data:application/json,example",
  ]) {
    const input = request("/");
    input.url = url;
    assert.equal(shouldLogApiSecurity(input), false, url);
  }
});

test("forwards only POST unlock to the login origin with no CORS or policies", async () => {
  const spec = JSON.parse(await readFile(new URL("../config/routes.oas.json", import.meta.url), "utf8"));
  const path = "/api/testing-tools/unlock";
  const pathItem = spec.paths[path];
  assert.equal(pathItem.post["x-internal"], true);
  assert.equal(pathItem["x-zuplo-path"].pathMode, "open-api");
  assert.deepEqual(Object.keys(pathItem).filter(key => !key.startsWith("x-")), ["post"]);
  const route = pathItem.post["x-zuplo-route"];
  const loginRoute = spec.paths["/api/auth/login"].post["x-zuplo-route"];
  assert.equal(route.corsPolicy, "none");
  assert.deepEqual(route.policies, { inbound: [] });
  assert.equal(route.handler.export, "urlForwardHandler");
  assert.equal(route.handler.module, "$import(@zuplo/runtime)");
  assert.deepEqual(route.handler.options, { baseUrl: loginRoute.handler.options.baseUrl });
  assert.equal(new URL(route.handler.options.baseUrl).protocol, "https:");
  assert.equal(new URL(`${route.handler.options.baseUrl}${path}`).pathname, path);
  assert.equal(pathItem.post.requestBody, undefined);
  for (const response of Object.values(pathItem.post.responses)) {
    assert.deepEqual(Object.keys(response), ["description"]);
  }
});
