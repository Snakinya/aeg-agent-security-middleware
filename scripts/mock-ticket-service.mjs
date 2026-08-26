import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

const host = "127.0.0.1";
const port = Number(process.env.MOCK_TICKET_PORT ?? 3999);
const tickets = [];

function send(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

const server = createServer((request, response) => {
  if (request.method === "GET" && request.url === "/tickets") {
    send(response, 200, { tickets });
    return;
  }
  if (request.method !== "POST" || request.url !== "/tickets") {
    send(response, 404, { error: "Route not found" });
    return;
  }

  let raw = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => {
    raw += chunk;
    if (raw.length > 32_768) request.destroy();
  });
  request.on("end", () => {
    try {
      const input = JSON.parse(raw || "{}");
      const ticket = {
        id: "T-" + randomUUID().slice(0, 8),
        title: String(input.title ?? "Untitled"),
        priority: String(input.priority ?? "normal"),
        idempotencyKey: String(request.headers["idempotency-key"] ?? ""),
        createdAt: new Date().toISOString(),
      };
      tickets.push(ticket);
      send(response, 201, ticket);
    } catch {
      send(response, 400, { error: "Invalid JSON" });
    }
  });
});

server.listen(port, host, () => {
  process.stdout.write(`Mock ticket service listening at http://${host}:${port}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
