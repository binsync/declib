package declib.jadxworker;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonObject;

class JadxServiceTest {
    @Test
    void pingDoesNotRequireLoadedInput() {
        try (JadxService service = new JadxService()) {
            Object result = service.dispatch("ping", new JsonObject());
            assertEquals("ok", ((Map<?, ?>) result).get("status"));
        }
    }

    @Test
    void loadedOperationsFailClearlyBeforeLoad() {
        try (JadxService service = new JadxService()) {
            assertThrows(
                    IllegalStateException.class,
                    () -> service.dispatch("info", new JsonObject()));
        }
    }

    @Test
    void unknownMethodIsRejected() {
        try (JadxService service = new JadxService()) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> service.dispatch("not_a_method", new JsonObject()));
        }
    }
}
