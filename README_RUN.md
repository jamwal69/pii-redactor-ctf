Run the detector locally

- Input: CSV with columns record_id,data_json (as provided)
- Output: redacted_output_candidate_full_name.csv

Command (Windows PowerShell):

```powershell
python .\detector_full_candidate_name.py "c:\Users\jamwa\Downloads\iscp_pii_dataset_-_Sheet1.csv"
```

Files:
- detector_full_candidate_name.py — main script
- DEPLOYMENT_STRATEGY.md — proposed deployment strategy
- redacted_output_candidate_full_name.csv — generated after running
