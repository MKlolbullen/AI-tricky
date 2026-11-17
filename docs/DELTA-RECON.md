# Delta recon

Open **Local workspace → Delta recon**, select a completed workflow run and
choose **Save this run as baseline**. Baselines persist in the local database
with immutable revisions. Select a subsequent run with the same entered
scope and workflow, then choose **Compare with baseline**.

The default view shows new and changed records. The filters also expose
unchanged records and records that were not observed in the current run.
Supported comparisons include host candidates from Subfinder/Assetfinder,
URLs from httprobe and the existing endpoint parsers, HTTP response metadata,
source files from the Web source collector, and saved API Surface endpoints.
Source file comparisons use captured byte hashes. Inferred API endpoints
compare their method and parameter names. Endpoint provenance remains visible.

A baseline key includes the canonical entered scope, executable node settings,
named connections, TCP ports and CLI scope mode. Canvas positions and display
labels can change without creating another baseline family. Budget, registered
input, binary and routing changes appear as coverage notices. Saving a new
revision requires the current revision, protecting concurrent edits. Historic
revisions remain selectable. An active run must finish or stop before it is
compared. A baseline requires a completed run with target execution enabled
and supported evidence. Review the saved coverage when choosing that run.

## Follow up on selected changes

Select up to eight new or changed rows and choose **Prepare selected follow-up**.
The resulting native HTTP workflow contains the distinct authorized URLs
from that selection. A hostname candidate maps to its HTTPS root. The request
list shows that destination before approval. Inferred routes with other HTTP
methods have no GET follow-up. Rows need supported current observations.

Load the workflow onto the canvas, or use its execution review to inspect
scope, exact URLs, request cost and limits before approving once. Preparation,
comparison and export read saved evidence. The approved follow-up shares the
existing native request budget, HTTP journal and run controls. Repeated
dispatch returns the same run. Its configuration records baseline revision,
comparison hash and selected record fingerprints. Captures, baseline bindings
and source coverage are checked again during review and dispatch.

## Coverage and evidence

New workflow executions save an input receipt per started node, including the
adapter contract hash, input hash, record count, upstream artifact IDs,
registered input snapshots and scope hash. Receipts retain hashes and
references. The coverage table shows completed, failed, skipped, cancelled
and reused nodes. Historical and reused nodes without fresh receipts have
unknown input coverage. Raw input values remain in their existing artifacts.

Failed nodes, partial captures, unparsed records, collection limits, gateway
denials and reached budgets produce notices. A missing record means only
that it was not observed. Finding status continues through the existing
operator review. Changed or missing baseline evidence disables follow-up
preparation and preserves the recorded baseline for inspection. Parser
upgrades require a fresh baseline.

Comparisons support up to 10,000 observations and comparable records, with
up to 2,000 artifacts per run. Each follow-up supports at most eight cited
observations. Choose fewer rows when a record has several observations.
