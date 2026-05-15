$milestone5_body = @'
As a security engineer, I want to integrate external Threat Intelligence into our Zeek pipeline so that known malicious IP/domain traffic is automatically flagged for analysis.

### Tasks
- [ ] Create local intel configuration directory (e.g., `/storage/PCAP/intel`).
- [ ] Construct `intel.dat` utilizing strict Tab-Separated Value (TSV) formatting for known malicious IPs/domains.
- [ ] Develop `config.zeek` script to load the Zeek Intel framework and link to `intel.dat`.
- [ ] Update Zeek Docker execution scripts to mount the new intel volume (`-v /storage/PCAP/intel:/data/intel`) and execute the config script.
'@

$milestone6_body = @'
As a SOC analyst, I want to build a proactive alerting framework within Kibana so that I am notified in real-time when suspicious network behaviors traverse the boundary.

### Tasks
- [ ] Provision alerting framework compatible with current stack (Kibana Actions/Watcher or ElastAlert2).
- [ ] Define baseline rule logic (e.g., trigger when `event.dataset:"zeek.notice"` and `notice.note:"Scan::Address_Scan"`).
- [ ] Configure external notification outputs via a simulated Discord, Slack, or Email Webhook.
'@

$milestone7_body = @'
As a SOC analyst, I want to design specific custom Kibana dashboards so that I can rapidly analyze top talkers, mapped infrastructure, and holistic security events from a centralized view.

### Tasks
- [ ] Design "Top Talkers" visual within Kibana parsing `zeek.conn` grouped by `orig_h` showing byte summaries.
- [ ] Design "Asset Discovery" visual filtering strictly by `zeek.dhcp` to map known hardware MACs to assigned IPs dynamically.
- [ ] Design "Security Overview" displaying a map visualization for external IPs alongside recent Zeek Notices.
'@

$milestone8_body = @'
As a security engineer, I want to simulate network attacks and test the corresponding platform reactions so that I can validate the effectiveness and physical response capabilities of our environment.

### Tasks
- [ ] Simulate Network Reconnaissance: Run an Nmap scan and verify `Scan::Port_Scan` triggers inside Kibana.
- [ ] Simulate Brute Force: Fail 5+ SSH authentication attempts and track the `auth_success=False` cascade within `zeek.ssh`.
- [ ] Simulate Malware Download: Exfiltrate a plaintext ZIP via `curl` and track the exact MIME type inside `zeek.files`.
- [ ] Verify the physical response protocols (e.g., block attacker IP in OpenWrt, quarantine MAC) can be executed successfully against these simulations.
'@

Write-Host "Creating User Stories..."

Write-Host "Creating Milestone 5 Issue..."
gh issue create --title "[User Story] Automated Threat Intelligence Feed" --body $milestone5_body --label "user-story" --assignee "@me"

Write-Host "Creating Milestone 6 Issue..."
gh issue create --title "[User Story] Real-Time Alerting Framework" --body $milestone6_body --label "user-story" --assignee "@me"

Write-Host "Creating Milestone 7 Issue..."
gh issue create --title "[User Story] Advanced SOC Visualizations" --body $milestone7_body --label "user-story" --assignee "@me"

Write-Host "Creating Milestone 8 Issue..."
gh issue create --title "[User Story] Validation via Anomaly Simulation" --body $milestone8_body --label "user-story" --assignee "@me"

Write-Host ""
Write-Host "All issues have been successfully created! They should now be available in your GitHub repository and Project Board."
