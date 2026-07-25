package declib.jadxworker;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.ICodeInfo;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.api.ResourcesLoader;
import jadx.api.data.impl.JadxNodeRef;
import jadx.api.metadata.ICodeNodeRef;
import jadx.api.metadata.annotations.NodeDeclareRef;
import jadx.core.xmlgen.ResContainer;

/**
 * Transport-independent, read-only JADX service.
 */
public final class JadxService implements AutoCloseable {
    private JadxDecompiler decompiler;
    private Path inputPath;
    private final Map<String, JavaClass> classesByRef = new LinkedHashMap<>();

    public Object dispatch(String method, JsonObject params) {
        return switch (method) {
            case "ping" -> Map.of("status", "ok", "version", "1");
            case "load" -> load(requiredString(params, "path"));
            case "info" -> info();
            case "list_classes" -> listClasses(
                    optionalString(params, "filter"), optionalInt(params, "limit", 1000));
            case "list_methods" -> listMethods(
                    optionalString(params, "class_ref"),
                    optionalString(params, "filter"),
                    optionalInt(params, "limit", 2000));
            case "list_fields" -> listFields(
                    optionalString(params, "class_ref"),
                    optionalString(params, "filter"),
                    optionalInt(params, "limit", 2000));
            case "class_source" -> classSource(requiredString(params, "ref"));
            case "method_source" -> methodSource(requiredString(params, "ref"));
            case "class_xrefs" -> classXrefs(requiredString(params, "ref"));
            case "method_xrefs" -> methodXrefs(
                    requiredString(params, "ref"),
                    optionalString(params, "direction"));
            case "field_xrefs" -> fieldXrefs(requiredString(params, "ref"));
            case "list_resources" -> listResources(
                    optionalString(params, "filter"), optionalInt(params, "limit", 2000));
            case "get_resource" -> getResource(
                    requiredString(params, "path"),
                    optionalInt(params, "max_bytes", 1024 * 1024));
            case "get_manifest" -> getManifest();
            case "shutdown" -> {
                close();
                yield Map.of("status", "closed");
            }
            default -> throw new IllegalArgumentException("Unknown worker method: " + method);
        };
    }

    private Map<String, Object> load(String pathValue) {
        close();
        inputPath = Path.of(pathValue).toAbsolutePath().normalize();
        File input = inputPath.toFile();
        if (!input.isFile()) {
            throw new IllegalArgumentException("Input file does not exist: " + inputPath);
        }

        JadxArgs args = new JadxArgs();
        args.setInputFile(input);
        args.setThreadsCount(Math.max(1, Math.min(4, Runtime.getRuntime().availableProcessors())));
        decompiler = new JadxDecompiler(args);
        decompiler.load();
        for (JavaClass cls : decompiler.getClassesWithInners()) {
            classesByRef.put(classRef(cls), cls);
        }
        return info();
    }

    private Map<String, Object> info() {
        requireLoaded();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("path", inputPath.toString());
        result.put("classes", decompiler.getClassesWithInners().size());
        result.put("resources", decompiler.getResources().size());
        result.put("errors", decompiler.getErrorsCount());
        result.put("warnings", decompiler.getWarnsCount());
        result.put("capabilities", List.of(
                "classes", "methods", "fields", "source", "xrefs",
                "resources", "manifest"));
        return result;
    }

    private List<Map<String, Object>> listClasses(String filter, int limit) {
        requireLoaded();
        Pattern pattern = compileFilter(filter);
        List<Map<String, Object>> result = new ArrayList<>();
        for (JavaClass cls : decompiler.getClassesWithInners()) {
            Map<String, Object> item = classDto(cls);
            if (matches(pattern, item)) {
                result.add(item);
                if (reachedLimit(result, limit)) {
                    break;
                }
            }
        }
        return result;
    }

    private List<Map<String, Object>> listMethods(String classRef, String filter, int limit) {
        requireLoaded();
        Pattern pattern = compileFilter(filter);
        List<Map<String, Object>> result = new ArrayList<>();
        for (JavaClass cls : selectedClasses(classRef)) {
            for (JavaMethod method : cls.getMethods()) {
                Map<String, Object> item = methodDto(method);
                if (matches(pattern, item)) {
                    result.add(item);
                    if (reachedLimit(result, limit)) {
                        return result;
                    }
                }
            }
        }
        return result;
    }

    private List<Map<String, Object>> listFields(String classRef, String filter, int limit) {
        requireLoaded();
        Pattern pattern = compileFilter(filter);
        List<Map<String, Object>> result = new ArrayList<>();
        for (JavaClass cls : selectedClasses(classRef)) {
            for (JavaField field : cls.getFields()) {
                Map<String, Object> item = fieldDto(field);
                if (matches(pattern, item)) {
                    result.add(item);
                    if (reachedLimit(result, limit)) {
                        return result;
                    }
                }
            }
        }
        return result;
    }

    private Map<String, Object> classSource(String ref) {
        JavaClass cls = findClass(ref);
        return Map.of(
                "ref", classRef(cls),
                "language", "java",
                "text", cls.getCode());
    }

    private Map<String, Object> methodSource(String ref) {
        JavaMethod method = findMethod(ref);
        return Map.of(
                "ref", methodRef(method),
                "class_ref", classRef(method.getDeclaringClass()),
                "language", "java",
                "text", extractMethodSource(method));
    }

    /**
     * JADX's JavaMethod#getCodeStr intentionally includes comments back to the
     * preceding blank line. For the first method in a class that can include
     * the class declaration itself. Use public code metadata to cut exactly
     * from the method declaration line through its matching END annotation.
     */
    private String extractMethodSource(JavaMethod method) {
        ICodeInfo codeInfo = method.getTopParentClass().getCodeInfo();
        if (!codeInfo.hasMetadata()) {
            return method.getCodeStr();
        }
        String code = codeInfo.getCodeStr();
        int definition = method.getDefPos();
        int lineBreak = code.lastIndexOf('\n', Math.max(0, definition - 1));
        int start = lineBreak == -1 ? 0 : lineBreak + 1;
        int[] nested = {0};
        Integer end = codeInfo.getCodeMetadata().searchDown(definition + 1, (position, annotation) -> {
            switch (annotation.getAnnType()) {
                case DECLARATION -> {
                    ICodeNodeRef node = ((NodeDeclareRef) annotation).getNode();
                    switch (node.getAnnType()) {
                        case CLASS, METHOD -> nested[0]++;
                        default -> {
                        }
                    }
                }
                case END -> {
                    if (nested[0] == 0) {
                        return position;
                    }
                    nested[0]--;
                }
                default -> {
                }
            }
            return null;
        });
        if (end == null || end < start || end > code.length()) {
            return method.getCodeStr();
        }
        return code.substring(start, end);
    }

    private List<Map<String, Object>> classXrefs(String ref) {
        return nodesToDtos(findClass(ref).getUseIn());
    }

    private Map<String, Object> methodXrefs(String ref, String directionValue) {
        JavaMethod method = findMethod(ref);
        String direction = directionValue == null ? "both" : directionValue.toLowerCase(Locale.ROOT);
        if (!List.of("callers", "callees", "both").contains(direction)) {
            throw new IllegalArgumentException(
                    "direction must be one of callers, callees, or both");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ref", methodRef(method));
        if (direction.equals("callers") || direction.equals("both")) {
            result.put("callers", nodesToDtos(method.getUseIn()));
        }
        if (direction.equals("callees") || direction.equals("both")) {
            result.put("callees", nodesToDtos(method.getUsed()));
        }
        return result;
    }

    private List<Map<String, Object>> fieldXrefs(String ref) {
        return nodesToDtos(findField(ref).getUseIn());
    }

    private List<Map<String, Object>> listResources(String filter, int limit) {
        requireLoaded();
        Pattern pattern = compileFilter(filter);
        List<Map<String, Object>> result = new ArrayList<>();
        for (ResourceFile resource : decompiler.getResources()) {
            Map<String, Object> item = resourceDto(resource);
            if (matches(pattern, item)) {
                result.add(item);
                if (reachedLimit(result, limit)) {
                    break;
                }
            }
        }
        return result;
    }

    private Map<String, Object> getResource(String pathValue, int maxBytes) {
        if (maxBytes < 1) {
            throw new IllegalArgumentException("max_bytes must be at least 1");
        }
        ResourceFile resource = findResource(pathValue);
        return resourceContent(resource, maxBytes);
    }

    private Map<String, Object> getManifest() {
        requireLoaded();
        for (ResourceFile resource : decompiler.getResources()) {
            if (resource.getType() == ResourceType.MANIFEST
                    || resource.getOriginalName().endsWith("AndroidManifest.xml")
                    || resource.getDeobfName().endsWith("AndroidManifest.xml")) {
                return resourceContent(resource, 1024 * 1024);
            }
        }
        throw new IllegalArgumentException("AndroidManifest.xml was not found");
    }

    private Map<String, Object> resourceContent(ResourceFile resource, int maxBytes) {
        ResContainer container = resource.loadContent();
        Map<String, Object> result = new LinkedHashMap<>(resourceDto(resource));
        result.putAll(containerContent(container, maxBytes));
        return result;
    }

    private Map<String, Object> containerContent(ResContainer container, int maxBytes) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("container_name", container.getName());
        result.put("container_type", container.getDataType().name().toLowerCase(Locale.ROOT));
        switch (container.getDataType()) {
            case TEXT, RES_TABLE -> {
                result.put("encoding", "utf-8");
                result.put("text", container.getText().getCodeStr());
                if (!container.getSubFiles().isEmpty()) {
                    List<Map<String, Object>> children = new ArrayList<>();
                    for (ResContainer child : container.getSubFiles()) {
                        Map<String, Object> childResult = new LinkedHashMap<>();
                        childResult.put("path", child.getName());
                        childResult.putAll(containerContent(child, maxBytes));
                        children.add(childResult);
                    }
                    result.put("children", children);
                }
            }
            case DECODED_DATA -> {
                byte[] data = container.getDecodedData();
                result.put("encoding", "base64");
                int outputSize = Math.min(data.length, maxBytes);
                result.put("size", outputSize);
                result.put("total_size", data.length);
                result.put("truncated", outputSize < data.length);
                result.put(
                        "data",
                        Base64.getEncoder().encodeToString(
                                outputSize == data.length
                                        ? data
                                        : Arrays.copyOf(data, outputSize)));
            }
            case RES_LINK -> result.putAll(rawResourceContent(container.getResLink(), maxBytes));
        }
        return result;
    }

    private Map<String, Object> rawResourceContent(ResourceFile resource, int maxBytes) {
        try {
            return ResourcesLoader.decodeStream(resource, (declaredSize, stream) -> {
                byte[] read = stream.readNBytes(maxBytes + 1);
                int outputSize = Math.min(read.length, maxBytes);
                boolean truncated = read.length > maxBytes
                        || (declaredSize >= 0 && declaredSize > outputSize);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("encoding", "base64");
                result.put("size", outputSize);
                if (declaredSize >= 0) {
                    result.put("total_size", declaredSize);
                }
                result.put("truncated", truncated);
                result.put(
                        "data",
                        Base64.getEncoder().encodeToString(
                                outputSize == read.length
                                        ? read
                                        : Arrays.copyOf(read, outputSize)));
                return result;
            });
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to read resource: " + resource.getOriginalName(),
                    exception);
        }
    }

    private List<JavaClass> selectedClasses(String classRef) {
        if (classRef == null || classRef.isBlank()) {
            return decompiler.getClassesWithInners();
        }
        return Collections.singletonList(findClass(classRef));
    }

    private JavaClass findClass(String ref) {
        requireLoaded();
        JavaClass direct = classesByRef.get(ref);
        if (direct != null) {
            return direct;
        }
        for (JavaClass cls : decompiler.getClassesWithInners()) {
            if (classRef(cls).equals(ref)
                    || cls.getRawName().equals(ref)
                    || cls.getFullName().equals(ref)) {
                return cls;
            }
        }
        throw new IllegalArgumentException("Class not found: " + ref);
    }

    private JavaMethod findMethod(String ref) {
        requireLoaded();
        int separator = ref.indexOf("->");
        if (separator < 1) {
            throw new IllegalArgumentException(
                    "Method reference must contain a declaring class and descriptor: " + ref);
        }
        JavaClass cls = findClass(ref.substring(0, separator));
        for (JavaMethod method : cls.getMethods()) {
            if (methodRef(method).equals(ref)) {
                return method;
            }
        }
        throw new IllegalArgumentException("Method not found: " + ref);
    }

    private JavaField findField(String ref) {
        requireLoaded();
        int separator = ref.indexOf("->");
        if (separator < 1) {
            throw new IllegalArgumentException(
                    "Field reference must contain a declaring class and descriptor: " + ref);
        }
        JavaClass cls = findClass(ref.substring(0, separator));
        for (JavaField field : cls.getFields()) {
            if (fieldRef(field).equals(ref)) {
                return field;
            }
        }
        throw new IllegalArgumentException("Field not found: " + ref);
    }

    private ResourceFile findResource(String pathValue) {
        requireLoaded();
        for (ResourceFile resource : decompiler.getResources()) {
            if (resource.getOriginalName().equals(pathValue)
                    || resource.getDeobfName().equals(pathValue)) {
                return resource;
            }
        }
        throw new IllegalArgumentException("Resource not found: " + pathValue);
    }

    private Map<String, Object> classDto(JavaClass cls) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("kind", "class");
        item.put("ref", classRef(cls));
        item.put("name", cls.getName());
        item.put("full_name", cls.getFullName());
        item.put("raw_name", cls.getRawName());
        item.put("package", cls.getPackage());
        return item;
    }

    private Map<String, Object> methodDto(JavaMethod method) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("kind", "method");
        item.put("ref", methodRef(method));
        item.put("class_ref", classRef(method.getDeclaringClass()));
        item.put("name", method.getName());
        item.put("full_name", method.getFullName());
        item.put("arguments", method.getArguments().stream().map(Objects::toString).toList());
        item.put("return_type", method.getReturnType().toString());
        item.put("access", method.getAccessFlags().toString());
        item.put("constructor", method.isConstructor());
        return item;
    }

    private Map<String, Object> fieldDto(JavaField field) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("kind", "field");
        item.put("ref", fieldRef(field));
        item.put("class_ref", classRef(field.getDeclaringClass()));
        item.put("name", field.getName());
        item.put("raw_name", field.getRawName());
        item.put("full_name", field.getFullName());
        item.put("type", field.getType().toString());
        item.put("access", field.getAccessFlags().toString());
        return item;
    }

    private Map<String, Object> resourceDto(ResourceFile resource) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("kind", "resource");
        item.put("path", resource.getDeobfName());
        item.put("original_path", resource.getOriginalName());
        item.put("type", resource.getType().name().toLowerCase(Locale.ROOT));
        item.put(
                "content_type",
                resource.getType().getContentType().name().toLowerCase(Locale.ROOT));
        return item;
    }

    private List<Map<String, Object>> nodesToDtos(List<? extends JavaNode> nodes) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (JavaNode node : nodes) {
            if (node instanceof JavaMethod method) {
                result.add(methodDto(method));
            } else if (node instanceof JavaField field) {
                result.add(fieldDto(field));
            } else if (node instanceof JavaClass cls) {
                result.add(classDto(cls));
            } else {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("kind", node.getClass().getSimpleName());
                item.put("name", node.getName());
                item.put("full_name", node.getFullName());
                result.add(item);
            }
        }
        return result;
    }

    private static String classRef(JavaClass cls) {
        return JadxNodeRef.forCls(cls).toString();
    }

    private static String methodRef(JavaMethod method) {
        return JadxNodeRef.forMth(method).toString();
    }

    private static String fieldRef(JavaField field) {
        return JadxNodeRef.forFld(field).toString();
    }

    private static Pattern compileFilter(String filter) {
        return filter == null || filter.isBlank()
                ? null
                : Pattern.compile(filter, Pattern.CASE_INSENSITIVE);
    }

    private static boolean matches(Pattern pattern, Map<String, Object> item) {
        if (pattern == null) {
            return true;
        }
        for (Object value : item.values()) {
            if (value != null && pattern.matcher(value.toString()).find()) {
                return true;
            }
        }
        return false;
    }

    private static boolean reachedLimit(List<?> values, int limit) {
        return limit > 0 && values.size() >= limit;
    }

    private static String requiredString(JsonObject params, String name) {
        String value = optionalString(params, name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required parameter: " + name);
        }
        return value;
    }

    private static String optionalString(JsonObject params, String name) {
        return params.has(name) && !params.get(name).isJsonNull()
                ? params.get(name).getAsString()
                : null;
    }

    private static int optionalInt(JsonObject params, String name, int defaultValue) {
        return params.has(name) && !params.get(name).isJsonNull()
                ? params.get(name).getAsInt()
                : defaultValue;
    }

    private void requireLoaded() {
        if (decompiler == null) {
            throw new IllegalStateException("No input is loaded");
        }
    }

    @Override
    public void close() {
        if (decompiler != null) {
            decompiler.close();
            decompiler = null;
        }
        classesByRef.clear();
        inputPath = null;
    }
}
