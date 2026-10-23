// Conformance runner for the Java SDK (tests/conformance/sdk/README.md).
//
//   java --enable-native-access=ALL-UNNAMED -cp bindings/java/target/classes bindings/java/conformance/Run.java <op> [key=value ...]
import ai.sourceorrery.OpenOptions;
import ai.sourceorrery.Project;
import ai.sourceorrery.ProjectSecret;
import ai.sourceorrery.Secret;
import ai.sourceorrery.SecretProperties;
import ai.sourceorrery.SecretReader;
import ai.sourceorrery.SourceOrreryException;
import ai.sourceorrery.VaultDescriptor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class Run {
    private static final List<String[]> LINES = new ArrayList<>();

    private static void line(String key, String value) {
        LINES.add(new String[] {key, value});
    }

    private static void properties(SecretProperties p) {
        line("version", p.version());
        line("enabled", String.valueOf(p.enabled()));
        line("content_type", p.contentType().orElse(""));
        line("reference", p.reference());
        p.tags().forEach((k, v) -> line("tag." + k, v));
    }

    private static void secret(Secret s) {
        line("value", s.value().exposeText());
        properties(s.properties());
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: Run <op> [key=value ...]");
            System.exit(2);
        }
        String op = args[0];
        Map<String, String> kv = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            int eq = args[i].indexOf('=');
            if (eq > 0) kv.put(args[i].substring(0, eq), args[i].substring(eq + 1));
        }
        String vault = kv.getOrDefault("vault", System.getenv().getOrDefault("SOURCEORRERY_TEST_VAULT", "development"));
        OpenOptions options = new OpenOptions(
                Optional.ofNullable(kv.get("home")),
                Optional.ofNullable(kv.get("passphrase")),
                Optional.ofNullable(kv.get("passphrase_file")),
                !"false".equals(kv.get("environment")),
                Optional.empty());
        try {
            if (op.equals("load")) {
                try (Project project = Project.load(Optional.ofNullable(kv.get("manifest")), options)) {
                    line("outcome", "ok");
                    line("project.name", project.name());
                    line("project.count", String.valueOf(project.secrets().size()));
                    line("project.names", String.join(",", project.secrets().stream().map(ProjectSecret::name).sorted().toList()));
                    for (ProjectSecret s : project.secrets()) line("secret." + s.env(), s.value().exposeText());
                }
            } else {
                try (SecretReader reader = SecretReader.open(vault, options)) {
                    switch (op) {
                        case "open" -> {
                            VaultDescriptor d = reader.descriptor();
                            line("outcome", "ok");
                            line("descriptor.name", d.name());
                            line("descriptor.protectors", String.join(",", d.protectors()));
                        }
                        case "get" -> {
                            try (Secret s = reader.get(kv.get("name"), Optional.ofNullable(kv.get("version")))) {
                                line("outcome", "ok");
                                secret(s);
                            }
                        }
                        case "get-newest-explicit" -> {
                            String newest = reader.properties(kv.get("name")).version();
                            try (Secret s = reader.get(kv.get("name"), newest)) {
                                line("outcome", "ok");
                                secret(s);
                            }
                        }
                        case "properties" -> {
                            line("outcome", "ok");
                            properties(reader.properties(kv.get("name"), Optional.ofNullable(kv.get("version"))));
                        }
                        case "resolve" -> {
                            try (Secret s = reader.resolve(kv.get("reference"))) {
                                line("outcome", "ok");
                                secret(s);
                            }
                        }
                        default -> {
                            System.err.println("unknown scenario op '" + op + "'");
                            System.exit(2);
                        }
                    }
                }
            }
        } catch (SourceOrreryException e) {
            LINES.clear();
            line("outcome", "error");
            line("code", e.code());
            line("message", e.detail());
            line("hint", e.hint());
            line("transient", String.valueOf(e.isTransient()));
            line("type", e.getClass().getSimpleName());
        }
        for (String[] kvp : LINES) System.out.println(kvp[0] + "\t" + kvp[1]);
    }
}
