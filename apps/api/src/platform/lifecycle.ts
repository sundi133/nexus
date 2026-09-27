/**
 * Process lifecycle shared by the HTTP server and shutdown: once draining, readiness fails so the
 * load balancer stops sending new requests, while requests already routed here still complete.
 */
export const lifecycle = { draining: false };
