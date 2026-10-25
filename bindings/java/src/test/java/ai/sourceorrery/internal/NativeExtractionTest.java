package ai.sourceorrery.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/** Extraction of the bundled library; needs no native library or vault. */
class NativeExtractionTest {
    private static final byte[] LIBRARY = {0x7f, 'E', 'L', 'F', 1, 2, 3};

    private static Path extract() throws IOException {
        return NativeExtraction.extract(new ByteArrayInputStream(LIBRARY), "libsourceorrery_ffi.so");
    }

    @Test
    void everyExtractionGetsItsOwnNewDirectory() throws IOException {
        Path first = extract();
        Path second = extract();
        try {
            assertArrayEquals(LIBRARY, Files.readAllBytes(first));
            assertNotEquals(first.getParent(), second.getParent());
            Path dir = first.getParent();
            assertTrue(dir.getFileName().toString().startsWith(NativeExtraction.PREFIX), dir.toString());
            assertEquals(Path.of(System.getProperty("java.io.tmpdir")).toRealPath(), dir.getParent().toRealPath());
            try (Stream<Path> entries = Files.list(dir)) {
                assertEquals(List.of(first), entries.toList());
            }
        } finally {
            for (Path path : List.of(first, first.getParent(), second, second.getParent())) {
                Files.deleteIfExists(path);
            }
        }
    }

    /** Run by {@link #nothingIsLeftBehindAtExit} in a separate JVM. */
    public static final class ExtractAndExit {
        public static void main(String[] args) throws IOException {
            System.out.println(extract());
        }
    }

    @Test
    void nothingIsLeftBehindAtExit() throws IOException, InterruptedException {
        String java = ProcessHandle.current().info().command().orElseThrow();
        Process child = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                ExtractAndExit.class.getName()).redirectErrorStream(true).start();
        String output = new String(child.getInputStream().readAllBytes()).trim();
        assertEquals(0, child.waitFor(), output);
        Path extracted = Path.of(output);
        assertTrue(extracted.getParent().getFileName().toString().startsWith(NativeExtraction.PREFIX), output);
        // The file is deleted first, then its directory: none of it remains.
        assertTrue(Files.notExists(extracted), output);
        assertTrue(Files.notExists(extracted.getParent()), output);
    }

    @Test
    void theDirectoryIsOwnerOnlyWherePermissionsExist() throws IOException {
        Path dir = NativeExtraction.privateDirectory();
        try {
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
            } else {
                assertOnlyTheOwner(dir);
            }
            assertTrue(Files.isDirectory(dir));
        } finally {
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void withAccessListsTheLibraryIsTheUsersAlone() throws IOException {
        Set<String> views = FileSystems.getDefault().supportedFileAttributeViews();
        assumeTrue(views.contains("acl") && !views.contains("posix"), "Windows only");
        Path extracted = extract();
        try {
            // Nothing is inherited from the temporary directory, which on
            // Windows is not always the user's alone.
            assertOnlyTheOwner(extracted.getParent());
            assertOnlyTheOwner(extracted);
            assertArrayEquals(LIBRARY, Files.readAllBytes(extracted));
        } finally {
            Files.deleteIfExists(extracted);
            Files.deleteIfExists(extracted.getParent());
        }
    }

    private static void assertOnlyTheOwner(Path path) throws IOException {
        UserPrincipal owner = Files.getOwner(path);
        List<AclEntry> acl = Files.getFileAttributeView(path, AclFileAttributeView.class).getAcl();
        assertEquals(1, acl.size(), path + ": " + acl);
        assertEquals(owner, acl.get(0).principal(), path + ": " + acl);
        assertEquals(AclEntryType.ALLOW, acl.get(0).type(), path + ": " + acl);
    }
}
