# Local Burp bridge

The AI-tricky Burp extension transfers selected HTTP exchanges to an
AI-tricky run and opens saved requests in Burp Repeater. Both components run
on the same machine. The bridge uses AI-tricky's API port, `8787` by default.
The Burp proxy listener is a separate setting.

## Install and pair

1. Build the extension with Maven and JDK 21.

   ```bash
   mvn -B -f integrations/burp-bridge/pom.xml verify
   ```

2. In Burp, open **Extensions → Installed → Add**, choose **Java**, and load
   `integrations/burp-bridge/target/ai-tricky-burp-bridge.jar`. The build targets
   Montoya API `2026.7`, supplied by Burp at runtime. GitHub CI also provides
   the JAR in the run’s **Artifacts** section.
3. In AI-tricky, open **Local workspace → HTTP history** and select a
   run with entered scope. **Generate Burp pairing**, then **Copy pairing**.
4. In Burp's **AI-tricky** tab, paste the pairing, enter the AI-tricky port if
   it differs, and click **Connect**. A single extension connection uses one
   run at a time. The pairing expires after one hour or on AI-tricky restart.
   In AI-tricky, **Revoke Burp pairing** removes access and clears pending
   deliveries. Replacing it invalidates the previous value. Treat the copied
   pairing as a credential and clear your clipboard after pasting.

## Burp to AI-tricky

Select up to 25 exchanges in Burp or use the menu on an HTTP message editor.
Choose **Import into AI-tricky**, review the destination run, and confirm. The
HTTP journal preserves the bytes supplied by Montoya, including duplicate
headers and binary bodies. It checks the URL, request target and authority
against the run's entered scope. A bad item rejects the batch. Identical bytes
and destination deduplicate within the run, independent of batch order. The
existing XML importer has its own import identity.

Each message needs a CRLF header block, at most 64 KiB of headers and 128 KiB
of body. Unsupported representations, oversized messages and scope mismatches
are reported in Burp. Imports appear as `burp_bridge` in HTTP History and as
imported matches in API Surface when the saved method and route agree. These
are externally supplied captures. Their headers and bodies may hold secrets.

## AI-tricky to Burp Repeater

Use **Open in Burp Repeater** in a saved HTTP exchange, under matching traffic
in API Surface, or from a finding's original HTTP capture. Burp opens a named
Repeater tab for review. Click **Send** in Burp to send it. The bridge itself
only transfers the saved bytes over loopback. Repeater uses Burp's own network
and session settings when you choose to send.

Incomplete, truncated, cancelled and authenticated metadata-only requests
are ineligible. For native plain HTTP recorded through a proxy, the bridge
converts the absolute, IP-based request target to origin form and sets the
original hostname as the Repeater service. Other eligible requests are
handed to Montoya with their saved bytes. Montoya and Repeater may normalize
how they represent or send the message. This is not a raw wire replay.

The pending queue holds 16 requests in memory per pairing and acknowledges
requests after Repeater opens them. A repeated click while an exchange is
queued reuses the same delivery. If Burp closes after opening a tab and before
acknowledging it, a later connection can reopen that tab's request.

[PortSwigger extension setup](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/set-up/manual-setup)
· [Montoya Repeater API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/repeater/Repeater.html)
