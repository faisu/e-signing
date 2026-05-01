import { BRIDGE_SOURCE, type BridgeRequest, type BridgeResponse } from "../shared/protocol";
import { isAllowedOrigin } from "../shared/origins";

document.documentElement.dataset.autodcrExtension = "1";

function postError(
  requestId: string,
  origin: string,
  code: string,
  message: string
): void {
  console.error("[bridge:content] posting bridge error response", {
    requestId,
    origin,
    code,
    message
  });
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
    console.debug("[bridge:content] dropped message from disallowed origin", {
      origin: event.origin
    });
    return;
  }

  const data = event.data as Partial<BridgeRequest> | undefined;
  if (!data || data.source !== BRIDGE_SOURCE || data.type !== "REQUEST") {
    return;
  }
  console.debug("[bridge:content] accepted page bridge request", {
    origin: event.origin,
    requestId: data.requestId ?? null,
    cmd: data.cmd ?? null
  });

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
    console.info("[bridge:content] forwarding request to service worker", {
      requestId: data.requestId,
      cmd: data.cmd
    });
    const response = await chrome.runtime.sendMessage({
      requestId: data.requestId,
      cmd: data.cmd,
      payload: data.payload
    });
    console.info("[bridge:content] service worker responded", {
      requestId: data.requestId,
      cmd: data.cmd,
      ok: response?.ok === true,
      errorCode: response?.error?.code ?? null
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
    console.error("[bridge:content] failed to reach service worker", {
      requestId: data.requestId,
      cmd: data.cmd,
      error: error instanceof Error ? error.message : String(error)
    });
    postError(
      data.requestId,
      event.origin,
      "RUNTIME_SEND_FAILED",
      error instanceof Error ? error.message : "Failed to send request to service worker."
    );
  }
});
