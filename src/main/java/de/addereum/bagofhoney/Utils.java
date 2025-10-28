package de.addereum.bagofhoney;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

public class Utils {
    /**
     * Generates/reads the host key from a stable location.
     * Path configurable via ENV BAGOFHONEY_HOSTKEY (default: ./data/hostkey.ser).
     */
    public static KeyPairProvider createSimpleHostKeyProvider() {
        String env = System.getenv("BAGOFHONEY_HOSTKEY");
        Path keyPath = Paths.get(env != null && !env.isBlank() ? env : "data/hostkey.ser").toAbsolutePath();

        try {
            Path parent = keyPath.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }

            // Create empty file if not present so we can set permissions if necessary.
            if (!Files.exists(keyPath)) {
                try {
                    Files.createFile(keyPath);
                } catch (FileAlreadyExistsException ignored) {
                }
            }

            // Attempt to set POSIX permissions (only effective on POSIX systems).
            try {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(keyPath, perms);
            } catch (UnsupportedOperationException | IOException ignored) {
                // Windows or non-POSIX file system -> ignore
            }
        } catch (IOException e) {
            // Fallback: Log in and continue. SimpleGeneratorHostKeyProvider creates the file on first use.
            System.err.println("Warning: konnte hostkey-Pfad nicht vorbereiten: " + e.getMessage());
        }

        // Provider uses the (now) stable file. SimpleGeneratorHostKeyProvider stores the key persistently.
        return new SimpleGeneratorHostKeyProvider(keyPath);
    }
}
