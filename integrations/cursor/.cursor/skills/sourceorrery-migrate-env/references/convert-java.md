# Converting Java and Kotlin code

SDK: `ai.sourceorrery:sourceorrery` on Maven Central. It needs Java 22 or
newer (the Foreign Function and Memory API); run the JVM with
`--enable-native-access=ALL-UNNAMED`. On an older Java, keep the
variables and start the program with `sourceorrery run --`.

```xml
<dependency>
  <groupId>ai.sourceorrery</groupId>
  <artifactId>sourceorrery</artifactId>
  <version><!-- latest from Maven Central --></version>
</dependency>
```

## One class for every read

```java
// src/main/java/com/example/Secrets.java
package com.example;

import ai.sourceorrery.Project;

/** Secrets from the SourceOrrery vault named in sourceorrery.toml. */
public final class Secrets {
    private static final Project PROJECT = Project.load(); // nearest sourceorrery.toml

    private Secrets() {}

    /** The value delivered as environment variable {@code name}. */
    public static String get(String name) {
        return PROJECT.env(name)
                .orElseThrow(() -> new IllegalStateException(name + " is not available from sourceorrery.toml"))
                .exposeText();
    }

    public static String getOrDefault(String name, String fallback) {
        return PROJECT.env(name).map(v -> v.exposeText()).orElse(fallback);
    }
}
```

## Replacements

| Before | After |
|--------|-------|
| `System.getenv("DATABASE_URL")` | `Secrets.get("DATABASE_URL")` |
| `Optional.ofNullable(System.getenv("TIMEOUT")).orElse("30")` | `Secrets.getOrDefault("TIMEOUT", "30")` |
| `Dotenv.load()` (dotenv-java) | delete, once every key is covered |

Kotlin: the same calls, `Secrets.get("DATABASE_URL")`.

## Frameworks

- **Spring Boot**: `${DATABASE_URL}` placeholders in
  `application.properties` / `application.yml` and `@Value("${...}")`
  resolve from the environment. The smallest change is to start the
  application under `sourceorrery run -- ./mvnw spring-boot:run` (or
  `java -jar`). To read the vault directly, add the values as a property
  source before the context starts:

  ```java
  var app = new SpringApplication(Application.class);
  var props = new java.util.HashMap<String, Object>();
  try (var project = ai.sourceorrery.Project.load()) {
      for (var s : project.secrets()) props.put(s.env(), s.value().exposeText());
  }
  app.setDefaultProperties(props);
  app.run(args);
  ```

- **Quarkus, Micronaut**: same choice; start under `sourceorrery run --`
  or feed the values into their configuration at start-up.

## Tests

`sourceorrery run -- ./mvnw test`, or let the code load the project.
