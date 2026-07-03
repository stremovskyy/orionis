import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

public final class OrdersClient {
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    private OrdersClient() {
    }

    public static void main(String[] args) throws Exception {
        String tokenURL = getenv("ORIONIS_TOKEN_URL", "http://localhost:8080/oauth/token");
        String billingURL = getenv("BILLING_URL", "http://localhost:8081/invoices");
        String clientID = getenv("ORIONIS_CLIENT_ID", "orders-service");
        String clientSecret = getenv("ORIONIS_CLIENT_SECRET", "orders-local-secret-change-me");
        String audience = getenv("ORIONIS_AUDIENCE", "billing-api");
        String scope = getenv("ORIONIS_SCOPE", "billing.invoice.create");

        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(HTTP_TIMEOUT)
                .build();

        TokenResponse token = requestToken(http, tokenURL, clientID, clientSecret, audience, scope);
        HttpResponse<String> billingResponse = createInvoice(http, billingURL, token.accessToken);

        System.out.printf("status=%d%n%s%n", billingResponse.statusCode(), billingResponse.body());
    }

    private static TokenResponse requestToken(
            HttpClient http,
            String tokenURL,
            String clientID,
            String clientSecret,
            String audience,
            String scope
    ) throws IOException, InterruptedException {
        String form = "grant_type=client_credentials"
                + "&audience=" + formValue(audience)
                + "&scope=" + formValue(scope);

        String basicCredentials = Base64.getEncoder()
                .encodeToString((clientID + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        HttpRequest request = HttpRequest.newBuilder(URI.create(tokenURL))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Basic " + basicCredentials)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "token request failed: status=" + response.statusCode() + " body=" + response.body()
            );
        }

        TokenResponse token = new TokenResponse(
                jsonString(response.body(), "access_token"),
                jsonString(response.body(), "token_type"),
                jsonLong(response.body(), "expires_in"),
                jsonString(response.body(), "scope")
        );

        if (token.accessToken.isBlank()) {
            throw new IllegalStateException("token response is missing access_token");
        }
        if (!"Bearer".equalsIgnoreCase(token.tokenType)) {
            throw new IllegalStateException("token response has unexpected token_type=" + token.tokenType);
        }
        if (token.expiresIn <= 0) {
            throw new IllegalStateException("token response has invalid expires_in=" + token.expiresIn);
        }

        return token;
    }

    private static HttpResponse<String> createInvoice(HttpClient http, String billingURL, String accessToken)
            throws IOException, InterruptedException {
        String body = "{\"order_id\":\"ord_demo_001\",\"amount\":1500}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(billingURL))
                .timeout(HTTP_TIMEOUT)
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(
                    "billing request failed: status=" + response.statusCode() + " body=" + response.body()
            );
        }

        return response;
    }

    private static String getenv(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String formValue(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String jsonString(String json, String field) {
        int valueStart = jsonValueStart(json, field);
        if (valueStart < 0 || valueStart >= json.length() || json.charAt(valueStart) != '"') {
            return "";
        }

        StringBuilder value = new StringBuilder();
        boolean escaping = false;
        for (int i = valueStart + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaping) {
                value.append(unescape(c));
                escaping = false;
                continue;
            }
            if (c == '\\') {
                escaping = true;
                continue;
            }
            if (c == '"') {
                return value.toString();
            }
            value.append(c);
        }

        return "";
    }

    private static long jsonLong(String json, String field) {
        int valueStart = jsonValueStart(json, field);
        if (valueStart < 0) {
            return 0;
        }

        int valueEnd = valueStart;
        while (valueEnd < json.length() && Character.isDigit(json.charAt(valueEnd))) {
            valueEnd++;
        }
        if (valueEnd == valueStart) {
            return 0;
        }

        return Long.parseLong(json.substring(valueStart, valueEnd));
    }

    private static int jsonValueStart(String json, String field) {
        String quotedField = "\"" + field + "\"";
        int fieldIndex = json.indexOf(quotedField);
        if (fieldIndex < 0) {
            return -1;
        }

        int colon = json.indexOf(':', fieldIndex + quotedField.length());
        if (colon < 0) {
            return -1;
        }

        int valueStart = colon + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }

        return valueStart;
    }

    private static char unescape(char c) {
        switch (c) {
            case '"':
            case '\\':
            case '/':
                return c;
            case 'b':
                return '\b';
            case 'f':
                return '\f';
            case 'n':
                return '\n';
            case 'r':
                return '\r';
            case 't':
                return '\t';
            default:
                return c;
        }
    }

    private static final class TokenResponse {
        final String accessToken;
        final String tokenType;
        final long expiresIn;
        final String scope;

        TokenResponse(String accessToken, String tokenType, long expiresIn, String scope) {
            this.accessToken = accessToken;
            this.tokenType = tokenType;
            this.expiresIn = expiresIn;
            this.scope = scope;
        }
    }
}
