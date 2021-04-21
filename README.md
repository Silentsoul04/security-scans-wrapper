# Generic wrapper for security scans 

This is a simple wrapper for scripts that runs on a given URL. 

The main goal is to automate bunch of secuity scans. 

Generates a HTML document and can send reports by email for investigation. 

Install

    pip install -U git+git@github.com:tristanlatr/security-scans-wrapper.git

Requires Python3.7 or later. 

Configure scripts with a config file: 

```ini
[general]
title = Security scans
scan_timeout = 24h
truncate_output = 10000 # (chars)

[mail]
from_email=me@gmail.com
smtp_server=smtp.gmail.com:587
smtp_auth=false
smtp_user=me@gmail.com
smtp_pass=P@assW0rd
smtp_ssl=true
max_attachments_size = 26214400 # (bytes) Will zip files together if the size is greater than 25MB

[--nikto]
description = Nikto - Web server scanner
# The "{{url}}" token will be filled with the value of --url argument
command = nikto -h {{url}} -o /tmp/nikto-report.html
# Attach the output files to the email. 
output_files = /tmp/nikto-report.html



[--rapidscan]
description = RapidScan - The Multi-Tool Web Vulnerability Scanner
command =   
    rm -rf /tmp/rapidscan-reports && mkdir /tmp/rapidscan-reports
    docker run -t --rm -v /tmp/rapidscan-reports:/reports kanolato/rapidscan {{url}}
# Accepts non reccursive globbing with '*'
output_files =
    /tmp/rapidscan-reports/*

[--wpscan]
description = WPScan - WordPress Security Scanner
command =   /usr/local/rvm/gems/default/wrappers/wpscan \
                --update --url {{url}} \
                --api-token {{wpscan-api-token}} 
                # Arbitrary interpolation values can be added, values should be supplied by arguments

```

Then run the tool of you choice and send report by email with:

```
python-3 -m security_scans_wrapper -c config.ini --mailto me@gmail.com --url http://exemple.com --rapidscan
```

You can use `--all` combined with `--no-<tool>` to run all configured tools and exclude some:

```
python-3 -m security_scans_wrapper -c config.ini --mailto me@gmail.com --url http://exemple.com --all --no-wpscan
```

Save the HTML report to file with the `--output` option. Default is `./report.html`, use `-` to indicate stdout. 

Additionaly, arbitrary interpolation values can be added to the scripts. This can be useful to configure authentication. 
The values should be supplied by arguments like `--arg KEY=VALUE`. The values will be replaced with asterixes in the emails for confidentiality. 

```
python-3 -m security_scans_wrapper -c config.ini --mailto me@gmail.com --url http://exemple.com --wpscan --arg wpscan-api-token=xxx
```
