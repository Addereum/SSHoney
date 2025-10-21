package de.addereum.bagofhoney;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    private static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");

        int udpPort = 4000;
        int tcpPort = 5000;
        int sshPort = Integer.parseInt(System.getenv().getOrDefault("SSH_PORT", "2222"));

        // --- SSH Honeypot thread ---
        Thread sshThread = new Thread(() -> {
            try {
                SSHHoney ssh = new SSHHoney(
                        "jdbc:postgresql://db:5432/honey", // wichtig: "db" statt "127.0.0.1"
                        "honey",
                        "honey"
                );
                log.info("Starting SSH honeypot on port {}", sshPort);
                ssh.start(sshPort);
            } catch (Exception e) {
                log.error("SSH honeypot error", e);
            }
        }, "ssh-honeypot");
        sshThread.setDaemon(true);
        sshThread.start();

        // --- UDP honeypot ---
        Thread udpThread = new Thread(() -> {
            try (DatagramSocket ds = new DatagramSocket(udpPort)) {
                log.info("UDP honeypot listening on {}", udpPort);
                byte[] buf = new byte[4096];
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    ds.receive(p);
                    String s = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8);
                    log.info("[UDP] {} {}:{} -> {} bytes: {}",
                            ZonedDateTime.now(), p.getAddress(), p.getPort(), p.getLength(), sanitize(s));
                    byte[] reply = ("OK " + System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8);
                    ds.send(new DatagramPacket(reply, reply.length, p.getAddress(), p.getPort()));
                }
            } catch (Exception e) {
                log.error("UDP listener error", e);
            }
        }, "udp-listener");
        udpThread.setDaemon(true);
        udpThread.start();

        // --- TCP honeypot ---
        Thread tcpThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(tcpPort)) {
                log.info("TCP honeypot listening on {}", tcpPort);
                while (true) {
                    try (Socket s = ss.accept()) {
                        s.setSoTimeout(2000);
                        InetAddress addr = s.getInetAddress();
                        int port = s.getPort();
                        byte[] buf = new byte[4096];
                        int read = s.getInputStream().read(buf);
                        String payload = read > 0 ? new String(buf, 0, read, StandardCharsets.UTF_8) : "";
                        log.info("[TCP] {} {}:{} -> {} bytes: {}",
                                ZonedDateTime.now(), addr, port, read, sanitize(payload));
                        s.getOutputStream().write(("HELLO\n").getBytes(StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        log.warn("TCP connection handling error: {}", e.toString());
                    }
                }
            } catch (Exception e) {
                log.error("TCP listener error", e);
            }
        }, "tcp-listener");
        tcpThread.setDaemon(true);
        tcpThread.start();

        Thread.currentThread().join();
    }

    private static String sanitize(String in) {
        if (in == null) return "";
        String s = in.replaceAll("\\p{Cntrl}", "?");
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
}
