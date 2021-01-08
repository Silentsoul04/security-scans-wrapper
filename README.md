# Generic wrapper for security scans 

This is a simple wrapper for scripts that runs on a given URL. 

The main goal is to automate bunch of secuity scans. 

Generates a HTML document and can send reports by email for investigation. 

Install

    pip install -r requirements.txt

Configure shell commands/scrtipts with a config file: 

```ini
[general]
title = Security scans


[mail]
from_email=me@gmail.com
smtp_server=smtp.gmail.com:587
smtp_auth=No
smtp_user=me@gmail.com
smtp_pass=P@assW0rd
smtp_ssl=Yes


[--nikto]
description = Nikto - Web server scanner
# The "{{url}}" token will be filled with the value of --url argument
command = nikto -h {{url}} -o /tmp/nikto-report.html
# Attach the output files to the email. (accepts non reccursive globbing with '*')
output_files = /tmp/nikto-report.html
popen_args = {"text":true}


[--rapidscan]
description = RapidScan - The Multi-Tool Web Vulnerability Scanner
command =   
    rm -rf /tmp/rapidscan-reports && mkdir /tmp/rapidscan-reports
    docker run -t --rm -v /tmp/rapidscan-reports:/reports kanolato/rapidscan {{url}}
output_files =
    /tmp/rapidscan-reports/RS-Vulnerability-Report
    /tmp/rapidscan-reports/RS-Debug-ScanLog 
# The command can be a shell script. But "shell":true needs to be enabled here. 
popen_args = {"text":true, "shell":true} 
```

Then run the tool of you choice and send report by email with:

```
./scan.py -c config.ini --mailto me@gmail.com --url http://exemple.com --rapidscan
```

You can use `--all` combined with `--no-<tool>` to run all configured tools but one:

```
./scan.py -c config.ini --mailto me@gmail.com --url http://exemple.com --all --no-wpscan
```

Save the HTML report to file with the `--output` option. Default will print HTML to stdout.  