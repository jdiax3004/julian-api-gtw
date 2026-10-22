import {
  environment,
  AkamaiApiSecurityPlugin,
  RuntimeExtensions,
  ZuploContext,
  ZuploRequest,
} from "@zuplo/runtime";
import { shouldLogApiSecurity } from "./api-security-logging";

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
    // The unlock route carries a passphrase and returns private definitions.
    // Exclude it before the existing JSON-only telemetry filter.
    shouldLog: async (request: ZuploRequest, context: ZuploContext) => {
      return shouldLogApiSecurity(request);
    },
  }),
);
}
