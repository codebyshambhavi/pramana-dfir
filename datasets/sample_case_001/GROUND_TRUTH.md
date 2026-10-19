# Ground truth for sample_case_001

Synthetic case for actor `mira.chen`. The evidence files are regenerated with `generate_case.py`.

## 1. Odd-hour login
- Events: `a78d2620d72b:EV-000001` (`system_log.csv#row=1`, 2026-10-18T02:17:00Z)
- Context: `9e1a17176fb8:EV-000001` (`chat_export.json#item=0`) records the same actor, device GPS, and IP location.
- Expected finding type: anomaly

## 2. Archive created then uploaded
- Events: `a78d2620d72b:EV-000002` (`system_log.csv#row=2`, archive created at 19:41Z) and `133704aeccc7:EV-000001` (`browser_history.csv#row=1`, uploaded at 19:44Z)
- Both events name `CASE-001.tar.gz`, actor `mira.chen`, and device `field-laptop-07`.
- Expected finding type: correlation

## 3. Photo location contradiction
- Events: `0db2bcad9a97:EV-000001` (`field_photo.jpg`, EXIF at 2026-10-18T02:24:00Z) and `9e1a17176fb8:EV-000001` (`chat_export.json#item=0`, device/IP location context)
- EXIF GPS is 37.7749, -122.4194; device GPS is 40.7128, -74.0060; synthetic IP `203.0.113.42` maps in the fixture to 38.9072, -77.0369.
- Expected finding type: contradiction
