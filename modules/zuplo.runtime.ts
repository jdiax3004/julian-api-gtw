import {
  environment,
  AkamaiApiSecurityPlugin,
  RuntimeExtensions,
  ZuploContext,
  ZuploRequest,
} from "@zuplo/runtime";

export function runtimeInit(runtime: RuntimeExtensions) {
  runtime.addPlugin(
  new AkamaiApiSecurityPlugin({
    hostname: "spdl.nonamesec.com",
    // index, provided by Akamai API Security
    index: 1,
    // Key provided by Akamai API Security
    key: environment.AKAMAI_API_SECURITY_KEY,
    // Enable the active prevention/protection feature
    enableProtection: true,
    // optional filter function to exclude requests
    shouldLog: async (request: ZuploRequest, context: ZuploContext) => {
      if (request.headers.get("content-type") !== "application/json") {
        return false;
      }
      return true;
    },
  }),
);
}