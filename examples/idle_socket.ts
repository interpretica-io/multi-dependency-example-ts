// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 midair <midair@localhost>
//
// Open one idle TCP connection (nothing is sent) and print how many
// seconds the server takes to close it. TypeScript version of the idle
// connection of the go_idle_connection test (H2); it settles no hypothesis
// by itself. The number is in whole seconds, as the test prints it.
//
// Usage: ts-node examples/idle_socket.ts <host> <port> [max_seconds=60]

import * as net from "net";

const [host, portArg, maxArg] = process.argv.slice(2);
const port = Number(portArg);
const maxSeconds = maxArg === undefined ? 60 : Number(maxArg);

if (!host || !Number.isInteger(port) || port < 1 || port > 65535 ||
    !Number.isFinite(maxSeconds)) {
    console.error("usage: idle_socket.ts <host> <port> [max_seconds=60]");
    process.exit(2);
}

const start = Date.now();
const elapsed = (): number => Math.round((Date.now() - start) / 1000);
const socket = net.connect({ host, port });

socket.on("data", () => { /* a reply is drained; only the close matters */ });
socket.on("error", (e: Error) => {
    console.error(`connection to ${host}:${port} failed: ${e.message}`);
    process.exit(1);
});
socket.on("close", () => {
    console.log(`idle (nothing sent): closed by the server after ` +
                `${elapsed()} s`);
    process.exit(0);
});

setTimeout(() => {
    console.log(`idle (nothing sent): still held at ${maxSeconds} s ` +
                `(hold time ${elapsed()} s)`);
    socket.destroy();
    process.exit(0);
}, maxSeconds * 1000);
