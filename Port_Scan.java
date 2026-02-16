import java.util.*;
import java.net.*;
import java.io.*;
import java.util.concurrent.*;

public class Port_Scan {

    private static final Map<Integer, String> SERVICES= new HashMap<>();

    static {
        SERVICES.put(1, "tcpmux");
        SERVICES.put(20, "ftp-data");
        SERVICES.put(21, "ftp");
        SERVICES.put(22, "ssh");
        SERVICES.put(23, "telnet");
        SERVICES.put(25, "smtp");
        SERVICES.put(53, "dns");
        SERVICES.put(80, "http");
        SERVICES.put(110, "pop3");
        SERVICES.put(111, "rpcbind");
        SERVICES.put(143, "imap");
        SERVICES.put(443, "https");
        SERVICES.put(993, "imaps");
        SERVICES.put(995, "pop3s");
        SERVICES.put(1723, "pptp");
        SERVICES.put(3306, "mysql");
        SERVICES.put(3389, "ms-wbt-server");
        SERVICES.put(5432, "postgresql");
        SERVICES.put(5900, "vnc");
        SERVICES.put(8080, "http-proxy");
    }

    public static void main(String[] args) {

        // This is the block for the CLI mode of the tool

        if (args.length == 0) {
            System.out.println("Usage: java -jar portscan.jar <ip> <port|range>\nExamples:");
            System.out.println("    java -jar portscan.jar scanme.nmap.org 1-100");
            System.out.println("    java -jar portscan.jar 192.168.1.1 80");
            System.out.println();
        }

        if (args.length >= 2) {
            String ip = args[0];
            String portSpec = args[1];
            int startPort = 1, endPort = 1024;
            if (portSpec.contains("-")) {
                String[] range = portSpec.split("-");
                startPort = Integer.parseInt(range[0]);
                endPort = Integer.parseInt(range[1]);
            } else {
                startPort = endPort = Integer.parseInt(portSpec);
            }
            startScan(ip, startPort, endPort);
            return;
        }

        // This is the block for the interactive mode of the tool
        Scanner in = new Scanner(System.in);
        System.out.println("Welcome to Port_Scan! - The tool that lets you scan machines\n" +
                "Please note that this tool is for scanning systems you own or are explicitly authorized to test and cannot be used to cause harm in any way!\n" +
                "Please enter the IP Address of the machine you want to scan: ");
        String ip = in.nextLine();
        System.out.println("You can specify a range that you want to be scanned by entering two numbers in this format 1-10000 (The default scan is a range from 1-1024)\n" +
                           "You can also enter one number to specify a single port that you want to scan\n" +
                           "Please enter your desired way of scanning or leave empty for a quick scan: ");
        String port = in.nextLine();

        int startPort = 1, endPort = 1024;
        if (!port.isEmpty()) {
            if (port.contains("-")) {
                String[] range = port.split("-");
                startPort = Integer.parseInt(range[0]);
                endPort = Integer.parseInt(range[1]);
                if(startPort <= 0 || endPort > 65535){
                    System.out.println("The entered range of: "+ port +" Is not a valid range number. Please enter a valid range (in the range of 1 to 65535)");
                    return;
                }
            } else {
                if(Integer.parseInt(port) <= 0 || Integer.parseInt(port) > 65535){
                    System.out.println("The port number:"+ port +" Is not a valid port number. Please enter a valid port number (one in the range of 1 to 65535)");
                    return;
                }
                startPort = endPort = Integer.parseInt(port);
            }
        }

        System.out.println(startPort==endPort? ("Initializing scanning process, the port that will be scanned: " + startPort) :
                ("Initializing scanning process, ports to scanned " + startPort + " - " + endPort + " Please sit back and relax."));

        startScan(ip, startPort, endPort);
        in.close();
    }

    private static void startScan(String ip, int startPort, int endPort){
        ExecutorService executor = Executors.newFixedThreadPool(100);

        for (int p = startPort; p <= endPort; p++) {
            final int sport = p;
            executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(ip, sport), 2000);
                    if(sport == 1935) {
                        VLCLauncher launcher = new VLCLauncher();
                        launcher.openNetworkStream(ip);
                    }
                    String service = SERVICES.getOrDefault(sport, "unknown");
                    System.out.printf("%d/tcp open %s%n", sport, service);
                } catch (Exception ignored) {}
            });
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(2, TimeUnit.MINUTES)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException i) {}

        System.out.println("Thank you for using this tool, you are AMAZING!");
    }

}





