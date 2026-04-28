import { BRIDGE_SOURCE, type BridgeRequest, type BridgeResponse } from "../shared/protocol";
import { isAllowedOrigin } from "../shared/origins";

document.documentElement.dataset.autodcrExtension = "1";

function postError(
  requestId: string,
  origin: string,
  code: string,
  message: string
): void {
  const response: BridgeResponse = {
    source: BRIDGE_SOURCE,
    type: "RESPONSE",
    requestId,
    ok: false,
    result: null,
    error: { code, message }
  };

  window.postMessage(response, origin);
}

window.addEventListener("message", async (event: MessageEvent) => {
  if (event.source !== window) {
    return;
  }

  if (!isAllowedOrigin(event.origin)) {
    return;
  }

  const data = event.data as Partial<BridgeRequest> | undefined;
  if (!data || data.source !== BRIDGE_SOURCE || data.type !== "REQUEST") {
    return;
  }

  if (!data.requestId || !data.cmd) {
    postError(
      data.requestId ?? "unknown",
      event.origin,
      "INVALID_REQUEST",
      "Missing requestId or cmd in bridge request."
    );
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      requestId: data.requestId,
      cmd: data.cmd,
      payload: data.payload
    });

    const bridgeResponse: BridgeResponse = {
      source: BRIDGE_SOURCE,
      type: "RESPONSE",
      requestId: data.requestId,
      ok: response?.ok === true,
      result: response?.result ?? null,
      error: response?.error ?? null
    };

    window.postMessage(bridgeResponse, event.origin);
  } catch (error) {
    postError(
      data.requestId,
      event.origin,
      "RUNTIME_SEND_FAILED",
      error instanceof Error ? error.message : "Failed to send request to service worker."
    );
  }
});
