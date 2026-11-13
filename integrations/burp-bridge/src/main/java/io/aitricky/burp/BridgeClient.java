package io.aitricky.burp;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

final class BridgeClient {
    record Pairing(String runId, String token) {}
    record Exchange(String url, String request, String response) {}
    record Delivery(String id, String exchange_id, String host, int port, boolean tls, String request) {}

    private static final Gson JSON = new Gson();
    private final HttpClient http = HttpClient.newBuilder()
            .proxy(new ProxySelector() {
                @Override public List<Proxy> select(URI uri) { return List.of(Proxy.NO_PROXY); }
                @Override public void connectFailed(URI uri, SocketAddress address, IOException failure) {}
            })
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(3)).build();
    private final URI base;
    private final Pairing pairing;

    BridgeClient(int port, String pairingJson) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Enter a valid AI-tricky port.");
        pairing = JSON.fromJson(pairingJson, Pairing.class);
        if (pairing == null || pairing.runId() == null || !pairing.runId().matches("[A-Za-z0-9_-]{1,64}")
                || pairing.token() == null || !pairing.token().matches("[A-Za-z0-9_-]{43}")) {
            throw new IllegalArgumentException("Paste the pairing copied from AI-tricky.");
        }
        base = URI.create("http://127.0.0.1:" + port + "/api/runs/" + pairing.runId() + "/burp-bridge/");
    }

    String runLabel() { return pairing.runId().substring(0, Math.min(pairing.runId().length(), 8)); }

    private JsonObject call(String path, String body) throws IOException, InterruptedException {
        var request = HttpRequest.newBuilder(base.resolve(path)).timeout(Duration.ofSeconds(8))
                .header("Authorization", "Bearer " + pairing.token()).header("Accept", "application/json");
        if (body == null) request.GET();
        else request.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        var response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        String responseBody;
        try (var stream = response.body()) {
            byte[] data = stream.readNBytes(300_001);
            if (data.length > 300_000) throw new IOException("AI-tricky returned an oversized response.");
            responseBody = new String(data, java.nio.charset.StandardCharsets.UTF_8);
        }
        if (response.statusCode() == 401) throw new IOException("Pairing expired or was revoked. Generate a new pairing in AI-tricky.");
        if (response.statusCode() >= 300) {
            String detail = "AI-tricky rejected the action (HTTP " + response.statusCode() + ").";
            try {
                var failure = JSON.fromJson(responseBody, JsonObject.class);
                if (failure != null && failure.has("detail") && failure.get("detail").isJsonPrimitive()) {
                    detail = failure.get("detail").getAsString();
                }
            } catch (RuntimeException ignored) { /* Keep the HTTP status for non-JSON failures. */ }
            throw new IOException(detail);
        }
        return JSON.fromJson(responseBody, JsonObject.class);
    }

    String importExchanges(List<Exchange> exchanges) throws IOException, InterruptedException {
        String body = JSON.toJson(java.util.Map.of("items", exchanges));
        if (body.length() > 7_900_000) throw new IOException("Selection exceeds the transfer limit. Select fewer exchanges.");
        var result = call("exchanges", body);
        return result.get("stored").getAsInt() + " stored, " + result.get("duplicates").getAsInt() + " already present.";
    }

    Delivery pending() throws IOException, InterruptedException {
        return JSON.fromJson(call("repeater", null).get("item"), Delivery.class);
    }

    void acknowledge(String id) throws IOException, InterruptedException {
        call("repeater/" + UUID.fromString(id) + "/ack", "{}");
    }
}
