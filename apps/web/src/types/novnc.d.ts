// The parts of noVNC's RFB client the Remote Assist viewer uses (the package ships no types).
declare module "@novnc/novnc" {
  export default class RFB extends EventTarget {
    constructor(target: HTMLElement, url: string, options?: { wsProtocols?: string[]; shared?: boolean; credentials?: { username?: string; password?: string } });
    scaleViewport: boolean;
    resizeSession: boolean;
    viewOnly: boolean;
    clipViewport: boolean;
    focusOnClick: boolean;
    background: string;
    sendCredentials(credentials: { username?: string; password?: string }): void;
    disconnect(): void;
    focus(): void;
  }
}
