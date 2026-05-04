from scan_engine import run_canonical_scan

urls = [
    "https://ispringfilter.com/url/url.php?u=71ddc7b738",
    "https://www.info-saisonpotal.com/"
]

for url in urls:
    print(f"\n--- Scanning: {url} ---")
    res = run_canonical_scan(url)
    print("Features extracted:")
    print({k: v for k, v in res.get('features', {}).items() if v != 0})
    print("Prediction:", res.get('prediction'))
    print("Confidence:", res.get('confidence'))
    if 'errors' in res and res['errors']:
        print("Errors:", res['errors'])
