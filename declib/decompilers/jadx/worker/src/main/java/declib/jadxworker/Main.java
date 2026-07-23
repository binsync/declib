package declib.jadxworker;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Line-delimited JSON request/response transport for {@link JadxService}.
 *
 * <p>JADX and all of its objects remain inside this JVM. DecLib only receives
 * structured values and stable raw Java/Dex references.</p>
 */
public final class Main {
    private static final Gson GSON = new Gson();

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
        try (JadxService service = new JadxService();
             BufferedReader input = new BufferedReader(
                     new InputStreamReader(System.in, StandardCharsets.UTF_8));
             PrintWriter output = new PrintWriter(System.out, true, StandardCharsets.UTF_8)) {
            String line;
            while ((line = input.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                JsonObject response = new JsonObject();
                try {
                    JsonObject request = JsonParser.parseString(line).getAsJsonObject();
                    JsonElement id = request.get("id");
                    response.add("id", id == null ? JsonNull.INSTANCE : id.deepCopy());
                    String method = request.get("method").getAsString();
                    JsonObject params = request.has("params")
                            ? request.getAsJsonObject("params")
                            : new JsonObject();
                    response.add("result", GSON.toJsonTree(service.dispatch(method, params)));
                } catch (Throwable throwable) {
                    JsonObject error = new JsonObject();
                    error.addProperty("type", throwable.getClass().getSimpleName());
                    error.addProperty(
                            "message",
                            throwable.getMessage() == null
                                    ? throwable.toString()
                                    : throwable.getMessage());
                    response.add("error", error);
                }
                output.println(GSON.toJson(response));
            }
        }
    }
}
