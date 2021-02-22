# Generic wrapper for security scans 

This is a simple wrapper for scripts that runs on a given URL. 

The main goal is to automate bunch of secuity scans. 

Generates a HTML document and can send reports by email for investigation. 

Install

    pip install -r requirements.txt

Configure scripts with a config file: 

```ini
[general]
title = Security scans
scan_timeout = 4h

[mail]
from_email=me@gmail.com
smtp_server=smtp.gmail.com:587
smtp_auth=false
smtp_user=me@gmail.com
smtp_pass=P@assW0rd
smtp_ssl=true


[--nikto]
description = Nikto - Web server scanner
# The "{{url}}" token will be filled with the value of --url argument
command = nikto -h {{url}} -o /tmp/nikto-report.html
# Attach the output files to the email. 
output_files = /tmp/nikto-report.html
popen_args = {"encoding":"utf-8", "errors":"replace"}


[--rapidscan]
description = RapidScan - The Multi-Tool Web Vulnerability Scanner
command =   
    rm -rf /tmp/rapidscan-reports && mkdir /tmp/rapidscan-reports
    docker run -t --rm -v /tmp/rapidscan-reports:/reports kanolato/rapidscan {{url}}
# Accepts non reccursive globbing with '*'
output_files =
    /tmp/rapidscan-reports/*
# The command can be a shell script. But "shell":true needs to be enabled here. 
popen_args = {"shell":true, "encoding":"utf-8", "errors":"replace"}

[--wpscan]
description = WPScan - WordPress Security Scanner
command =   /usr/local/rvm/gems/default/wrappers/wpscan \
                --update --url {{url}} \
                --api-token {{wpscan-api-token}} 
                # Arbitrary interpolation values can be added, values should be supplied by arguments
popen_args = {"shell":true, "encoding":"utf-8", "errors":"replace"}
```

Then run the tool of you choice and send report by email with:

```
./scan.py -c config.ini --mailto me@gmail.com --url http://exemple.com --rapidscan
```

You can use `--all` combined with `--no-<tool>` to run all configured tools and exclude some:

```
./scan.py -c config.ini --mailto me@gmail.com --url http://exemple.com --all --no-wpscan
```

Save the HTML report to file with the `--output` option. Default is `./report.html`, use `-` to indicate stdout. 

Additionaly, arbitrary interpolation values can be added to the scripts. This can be useful to configure authentication. 
The values should be supplied by arguments like `--arg KEY=VALUE`. 

```
./scan.py -c config.ini --mailto me@gmail.com --url http://exemple.com --wpscan --arg wpscan-api-token=xxx
```