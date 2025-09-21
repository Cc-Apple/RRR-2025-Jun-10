Victim Report Template — README
=================================
What this is:
- A simple CSV template to crowd-source incident reports for suspected device-level surveillance or harassment.
- Keep one row per incident.

How to fill:
- timestamp_local: local time with timezone, e.g., 2025-06-14T21:05:00+07:00
- consent_to_publish: yes/no
- reporter_role: victim/witness/researcher/journalist/other
- country, city_or_district, latitude, longitude: required for mapping (lat/lon optional but helpful)
- incident_start_utc / incident_end_utc: ISO 8601 in UTC, e.g., 2025-06-14T14:05:00Z
- device_type: e.g., iPhone 12 mini
- os_version: e.g., iOS 18.5 (22F76)
- mdm_present: true/false/unknown
- suspected_vector: Wi-Fi/Bluetooth/SMS/MDM/ConfigProfile/Unknown (multiple allowed, semicolon-separated)
- physical_effects: concise, comma-separated
- psychological_effects: concise, comma-separated
- key_log_terms: e.g., RTCR;JetsamEvent;Stacks;Pegasus;Biome;EcosystemAnalytics
- biome_metrics_found: yes/no
- biome_metric_values: e.g., 400;2500
- jetsam_events_count, stacks_count: integers if known
- evidence_hashes: semicolon-separated SHA256 (preferred) or MD5
- evidence_links: optional links to storage locations
- notes: any extra context, IDs, etc.

Integrity tips:
- Always compute SHA256 for any shared files or screenshots.
- Keep original filenames and avoid re-saving images (to preserve EXIF timestamps).

— Generated 2025-08-19T01:56:01.960148+07:00