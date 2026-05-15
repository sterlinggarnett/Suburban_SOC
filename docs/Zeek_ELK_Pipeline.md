# End-to-End Network Analysis Pipeline Setup

This document serves as a complete recap of everything we accomplished to build your network packet analysis lab. You successfully built a pipeline that takes raw packet captures, converts them to structured JSON logs, and ships them directly into an ELK database for visual analysis.

## Architecture Overview

1. **Zeek (Docker):** Ingests raw `.pcap` files and outputs detailed `.log` files in JSON format.
2. **Filebeat (Ubuntu WSL):** Monitors the Zeek log directory and securely ships new lines to Logstash.
3. **Logstash (Docker-ELK):** Receives the Filebeat data on port 5044 and pipelines it into the database.
4. **Elasticsearch (Docker-ELK):** The core database that permanently stores the JSON logs.
5. **Kibana (Docker-ELK):** The graphical dashboard used to search and visualize the data.

---

## 1. Preparing the Environment && Generating Data
We started by setting up a clean directory for your data at `/storage` inside your Ubuntu WSL environment. We used a script to pull standard, real-world PCAP files (HTTP, DHCP, DNS, etc.) from Wireshark's developer repositories directly into `/storage/PCAP`.

Once the `.pcap` files were staged, we used the official Zeek Docker container to process them:

```bash
docker run --rm \
  -v /storage/PCAP:/data \
  -w /data/zeek_logs \
  zeek/zeek \
  zeek -r /data/http.pcap LogAscii::use_json=T
```

> [!NOTE]
> **Why `.log` extensions?** Even though we used the `use_json=T` flag, Zeek is hardcoded to output its files with a `.log` extension (e.g., `conn.log`). We verified that the internal contents were perfectly formatted JSON text.

---

## 2. Setting Up the Log Shipper (Filebeat)
To get the data out of `/storage/PCAP/zeek_logs/` and into your database, we installed Filebeat directly on your Ubuntu environment. 

We made two critical configurations to `/etc/filebeat/filebeat.yml`:
1. **The Input:** We pointed Filebeat to the logs by supplying the path `/storage/PCAP/zeek_logs/*.log` and setting `enabled: true`.
2. **The Output:** We disabled the default Elasticsearch output and enabled the Logstash output. 

### Troubleshooting the Network Link
We ran into an `"i/o timeout"` issue when Filebeat tried connecting to Logstash via a VirtualBox IP (`192.168.56.1`). Because Filebeat lives inside WSL, resolving Docker Desktop IPs can be tricky. 

**The Fix:** We changed the Filebeat output host to `localhost:5044`. Docker Desktop natively proxies `localhost` calls cleanly across the Windows/WSL boundary, resulting in an instant `talk to server... OK` connection!

> [!IMPORTANT]
> **Filebeat 9.x requires `type: filestream`** — the legacy `type: log` input is deprecated and causes a **fatal startup error** in Filebeat 9.x. Always use `filestream` with the `ndjson` parser block.

---

## 3. Configuring the Receiver (Logstash)
You already had a fully configured ELK stack running via Docker Desktop (`docker-elk`). Because the Logstash container in that stack handles the ingestion, we bypassed creating a standalone container.

In order for Logstash to acknowledge Filebeat's connection, you verified that its configuration file (`logstash.conf` inside your `docker-elk` project directory) contained the correct input block:
```ruby
input {
  beats {
    port => 5044
  }
}
```

---

## 4. Visualizing the Data (Kibana)
With the pipeline fully flowing (Zeek -> Filebeat -> Logstash), the final step was simply to view the data.

1. You navigated to `http://localhost:5601`.
2. In **Stack Management > Data Views**, you created a dynamic index pattern by defining `logstash-*`, allowing Kibana to map all incoming data from Logstash automatically.
3. You set the timestamp field to `@timestamp`.

> [!WARNING]
> **PCAP Timestamp Gotcha:** In the Discover tab, the data initially appeared completely blank. This was because Zeek extracts raw timestamps based on *when the PCAP was originally recorded* (some Wireshark samples date back to 2004). Opening the calendar filter and expanding the search to the **"Last 25 Years"** successfully revealed all of the hidden log data!
