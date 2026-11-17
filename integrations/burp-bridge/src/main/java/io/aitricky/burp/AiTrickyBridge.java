package io.aitricky.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutionException;

public final class AiTrickyBridge implements BurpExtension {
    private static final int MAX_SELECTION = 25;
    private static final int MAX_MESSAGE_BYTES = 196_608;
    private volatile BridgeClient client;
    private MontoyaApi api;
    private JPanel panel;
    private JLabel status;
    private JButton connect;
    private JButton disconnect;
    private Timer timer;
    private SwingWorker<?, ?> running;
    private String lastOpened;

    @Override
    public void initialize(MontoyaApi montoya) {
        api = montoya;
        api.extension().setName("AI-tricky Bridge");
        api.extension().registerUnloadingHandler(() -> SwingUtilities.invokeLater(this::disconnect));
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<HttpRequestResponse> selection = event.selectedRequestResponses();
                if (selection.isEmpty()) {
                    selection = event.messageEditorRequestResponse().map(editor -> List.of(editor.requestResponse())).orElseGet(List::of);
                }
                if (selection.isEmpty() || client == null) return List.of();
                var selected = List.copyOf(selection);
                var item = new JMenuItem("Import into AI-tricky (" + selected.size() + ")");
                item.setEnabled(selected.size() <= MAX_SELECTION);
                item.addActionListener(ignored -> importSelected(selected));
                return List.of(item);
            }
        });
        SwingUtilities.invokeLater(this::createTab);
    }

    private void createTab() {
        panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        var form = new JPanel(new FlowLayout(FlowLayout.LEADING));
        var port = new JTextField("8787", 6);
        var pairing = new JPasswordField(32);
        connect = new JButton("Connect");
        disconnect = new JButton("Disconnect");
        disconnect.setEnabled(false);
        var portLabel = new JLabel("AI-tricky port");
        portLabel.setLabelFor(port);
        var pairingLabel = new JLabel("Run pairing");
        pairingLabel.setLabelFor(pairing);
        form.add(portLabel); form.add(port); form.add(pairingLabel); form.add(pairing); form.add(connect); form.add(disconnect);
        status = new JLabel("Copy a pairing from AI-tricky → HTTP history, then paste it here.");
        panel.add(form, BorderLayout.NORTH);
        panel.add(status, BorderLayout.CENTER);
        timer = new Timer(2000, ignored -> poll());
        connect.addActionListener(ignored -> {
            char[] key = pairing.getPassword();
            try {
                client = new BridgeClient(Integer.parseInt(port.getText().trim()), new String(key));
                pairing.setText("");
                connect.setEnabled(false);
                disconnect.setEnabled(true);
                status.setText("Connecting to run " + client.runLabel() + "…");
                timer.start();
                poll();
            } catch (RuntimeException failure) {
                status.setText("Enter the local port and paste a valid run pairing.");
            } finally {
                java.util.Arrays.fill(key, '\0');
            }
        });
        disconnect.addActionListener(ignored -> disconnect());
        api.userInterface().registerSuiteTab("AI-tricky", panel);
    }

    private void disconnect() {
        client = null;
        lastOpened = null;
        if (timer != null) timer.stop();
        if (running != null) running.cancel(true);
        running = null;
        if (status == null) return;
        connect.setEnabled(true);
        disconnect.setEnabled(false);
        status.setText("Disconnected. Revoke the pairing in AI-tricky to clear its queue.");
    }

    private void importSelected(List<HttpRequestResponse> selected) {
        var active = client;
        if (active == null) return;
        if (running != null) {
            JOptionPane.showMessageDialog(panel, "The bridge is busy. Try the selection again in a moment.");
            return;
        }
        if (JOptionPane.showConfirmDialog(panel, "Import " + selected.size() + " exchange(s) into run " + active.runLabel()
                + "? Saved headers and bodies may contain credentials.", "Import into AI-tricky", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        status.setText("Importing selected exchanges…");
        run(active, () -> {
            var exchanges = new ArrayList<BridgeClient.Exchange>();
            for (var pair : selected) {
                exchanges.add(new BridgeClient.Exchange(pair.request().url(), encode(pair.request().toByteArray()),
                        pair.hasResponse() ? encode(pair.response().toByteArray()) : null));
            }
            return active.importExchanges(exchanges);
        }, message -> {
            status.setText(message);
            JOptionPane.showMessageDialog(panel, message, "AI-tricky import", JOptionPane.INFORMATION_MESSAGE);
        }, true);
    }

    private static String encode(ByteArray bytes) {
        if (bytes.length() > MAX_MESSAGE_BYTES) throw new IllegalArgumentException("Selection contains an oversized HTTP message.");
        return Base64.getEncoder().encodeToString(bytes.getBytes());
    }

    private void poll() {
        var active = client;
        if (active == null || running != null) return;
        run(active, active::pending, item -> {
            if (item == null) {
                if (status.getText().startsWith("Connecting") || status.getText().startsWith("Bridge error")) {
                    status.setText("Connected to run " + active.runLabel() + ". Ready to receive Repeater requests.");
                }
                return;
            }
            if (!item.id().equals(lastOpened)) {
                var message = ByteArray.byteArray(Base64.getDecoder().decode(item.request()));
                var service = HttpService.httpService(item.host(), item.port(), item.tls());
                api.repeater().sendToRepeater(HttpRequest.httpRequest(service, message), "AI-tricky " + item.exchange_id().substring(0, 8));
                lastOpened = item.id();
                status.setText("Saved request opened in Repeater for manual review.");
            }
            run(active, () -> { active.acknowledge(item.id()); return null; }, ignored -> {}, false);
        }, false);
    }

    private <T> void run(BridgeClient active, java.util.concurrent.Callable<T> action,
                         java.util.function.Consumer<T> done, boolean showError) {
        running = new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return action.call(); }
            @Override protected void done() {
                if (running != this || client != active) return;
                running = null;
                try {
                    done.accept(get());
                } catch (ExecutionException | InterruptedException | RuntimeException failure) {
                    Throwable cause = failure instanceof ExecutionException ? failure.getCause() : failure;
                    String message = cause instanceof java.io.IOException || cause instanceof IllegalArgumentException
                            ? cause.getMessage() : "Bridge could not complete the action.";
                    status.setText("Bridge error · " + message);
                    if (showError) JOptionPane.showMessageDialog(panel, message, "AI-tricky import", JOptionPane.WARNING_MESSAGE);
                }
            }
        };
        running.execute();
    }
}
