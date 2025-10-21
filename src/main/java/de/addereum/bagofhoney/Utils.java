package de.addereum.bagofhoney;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

import java.nio.file.Paths;

public class Utils {
    public static KeyPairProvider createSimpleHostKeyProvider() {
        // erstellt/benutzt hostkey unter ./hostkey.ser
        return new SimpleGeneratorHostKeyProvider(Paths.get("hostkey.ser"));
    }
}
