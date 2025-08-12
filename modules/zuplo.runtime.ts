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
      hostname: "https://spdl.nonamesec.com/engine",
      // index, provided by Akamai API Security
      index: 1,
      // Key provided by Akamai API Security
      key: environment.AKAMAI_API_SECURITY_KEY,
      // Enable the active prevention/protection feature
      enableProtection: true,
    }),
  );
}