# Maltiverse Feed SPLUNK ENTERPRISE SECURITY Connector
Connection script to integrate Maltiverse feeds into Splunk Enterprise Security

```
usage: maltiverse-splunk.py [-h] --email MALTIVERSE_EMAIL --password MALTIVERSE_PASSWORD --feed MALTIVERSE_FEED[--output-dir OUTPUTDIR] [--verbose]

optional arguments:
  -h, --help            show this help message and exit
  --email MALTIVERSE_EMAIL
                        Specifies Maltiverse email for login. Required
  --password MALTIVERSE_PASSWORD
                        Specifies Maltiverse password for login. Required
  --feed MALTIVERSE_FEED
                        Specifies Maltiverse Feed ID to retrieve. Required
  --output-dir OUTPUTDIR
                        Specifies the CSV output directory.
  --verbose             Shows extra information during ingestion
```

## Example 1 - Retrieve "Malicious IP" feed, full download
maltiverse-splunk.py --email EMAIL --password PASSWORD --feed uYxZknEB8jmkCY9eQoUJ 



