#!/usr/bin/env python3
"""
Generic wrapper for any tools that runs on a given URL. 
Generates a HTML document and can send reports by email. 
Secuity scans are the main usage. 
"""

import sys
import subprocess
from typing import Dict, Any, Iterable, List
import smtplib
import json
import argparse
import configparser
import functools
import pathlib
import io
import glob
import shlex
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText

import attr
import markdown
from ansi2html import Ansi2HTMLConverter
ansi2HTMLconverter = Ansi2HTMLConverter(inline=True, linkify=True)

print = functools.partial(print, file=sys.stderr)

@attr.s(auto_attribs=True, frozen=True)
class Process:
  """
  Run arbitrary commands with subprocess from string command with '{{url}}' interpolation and popen args as JSON. 
  """
  command: str

  popen_args: Dict[str, Any] = attr.ib(converter=json.loads)

  def run(self, url) -> subprocess.CompletedProcess:
    """
    Run the command with the given URL. It substitutes the '{{url}}' from the command. 
    """
    # substiture template
    cmd = self.command.replace('{{url}}', shlex.quote(url)) if (
      '{{url}}' in self.command ) else self.command
    # cast command to right format depending shell = True
    _cmd = shlex.split(cmd) if not self.popen_args.get('shell', False) else cmd
    print(f"Running: '{_cmd}'\n(Popen arguments: {self.popen_args})")
    p = subprocess.run(
      _cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **self.popen_args)
    p.args = cmd.strip()
    return p


@attr.s(auto_attribs=True, frozen=True)
class ReportItem:
    """
    Transform a process CompletedProcess object to pseudo markdown/HTML.

    Strore output files as Path. 
    """

    process: subprocess.CompletedProcess
    description: str  

    def _get_filepaths(files: List[str]) -> List[pathlib.Path]:

      # find output files with globbing if any
      globbed = list()
      for f in (files if isinstance(files, list) else [files]):
        found_files = glob.glob(f)
        if not found_files:
          print(f"File not found for path {f}")
        else:
          globbed.extend(found_files)

      paths = [ pathlib.Path(f) for f in globbed  ]
      files = list()
      for path in paths:
        if path.exists():
          if path.is_file():
            files.append(path)
      if files:
        print(f"Output file(s): {', '.join(f.as_posix() for f in files)}")
      return files


    output_files: List[pathlib.Path] = attr.ib(factory=list, converter=_get_filepaths)
    
    def as_markdown(self) -> str:
      ansi_result = self.process.stdout + self.process.stderr
      output_files = "" if not self.output_files else f"_Output file(s): {', '.join(f.name for f in self.output_files)}_"
      newline = '\n'
      return f"""
## {self.description}

<code>
{self.process.args.replace(newline, '<br />')}
</code>

<strong>Result</strong> <br />

<div class="body_foreground body_background" style="font-size: 10;" >
<pre class="ansi2html-content">
{ansi2HTMLconverter.convert(ansi_result, full=False)}
</pre>
</div>

{output_files}
"""


@attr.s(auto_attribs=True, frozen=True)
class Report:
  """
  Transform a collection of ReportItem into a HTML document. 
  """

  items: Iterable[ReportItem]
  title: str
  url: str
  datetime: str # = datetime.now().isoformat(timespec='seconds')

  def _as_markdown(self) -> str:
    md = f"# {self.title} - {self.url} - {self.datetime}\n"
    md += "[TOC]\n"
    for item in self.items:
      md += f"{item.as_markdown()}"
    return md

  def as_html(self) -> str:
    html = markdown.markdown(self._as_markdown(), 
      extensions=['pymdownx.highlight', 'pymdownx.superfences', 
                  'pymdownx.details', 'pymdownx.magiclink', 'markdown.extensions.toc'])
    return f"""<!DOCTYPE html>
<html>
<head>
{ansi2HTMLconverter.produce_headers()}
</head>
<body>
<div class="container">
{html}
</div>
</body>
</html>
"""


@attr.s(auto_attribs=True, frozen=True)
class MailSender:
    """
    Fire the email reports. 
    """

    from_email: str
    smtp_server: str

    smtp_ssl: bool = attr.ib(default=False, converter=json.loads)
    smtp_auth: bool = attr.ib(default=False, converter=json.loads)
    
    smtp_user: str = ""
    smtp_pass: str = ""

    def _send_mail(self, message: MIMEMultipart, email_to: List[str]) -> None:
        """Raw sendmail"""
        # Connecting and sending
        server = smtplib.SMTP(self.smtp_server)
        server.ehlo_or_helo_if_needed()
        # SSL
        if self.smtp_ssl:
            server.starttls()
        # SMTP Auth
        if self.smtp_auth:
            server.login(self.smtp_user, self.smtp_pass)
        # Send Email
        server.sendmail(self.from_email, email_to, message.as_string())
        server.quit()

    # Send email report with status and timestamp
    def send(self, report: Report, email_to: List[str]) -> None:
        """Build MIME message based on report object and send mail. """

        # Building message
        message = MIMEMultipart("html")
        message[
            "Subject"
        ] = f"{report.title} - {report.url} - {report.datetime}"
        message["From"] = self.from_email
        message["To"] = ",".join(email_to)

        # Email body
        body = report.as_html()

        message.attach(MIMEText(body, "html"))

         # Attachments
        for item in report.items:
          for f in item.output_files:
            # Read the WPSCan output
            attachment = io.BytesIO(f.read_bytes())
            part = MIMEApplication(attachment.read(), Name=f.name)
            # Add header as key/value pair to attachment part
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={f.name}",
            )
            # Attach the report
            message.attach(part)

        # Connecting and sending
        self._send_mail(message, email_to)
        print(f"Mail sent: {message['Subject']} to {email_to}")


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="""Generic wrapper for any tools that runs on a given URL. 
Generates a HTML document and can send reports by email. 
Secuity scans are the main usage. 
""", 
      epilog="Configure tools in the config file and activate then with --<tool>.\nConfig exemple:\n"
             "[--nikto]\ndescription = Nikto web server scanner\ncommand = nikto -h $url\n\n"
             "Then use --nikto to run nikto scan on a given URL. You can also specify --all --no-nikto to exclude tools.", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', '-c', help="Configuration file(s).", action="extend", nargs="+", required=True)
    parser.add_argument('--url', '-u', help="URL to scan.")
    parser.add_argument('--mailto', '-m', help="Send report by email to recipient(s).", action="extend", nargs="+")
    parser.add_argument('--output', '-o', help="Save report to HTML file. ", 
                        default='-', type=argparse.FileType('w', encoding='UTF-8'))
    
    return  parser


def get_enabled_tools(configured_tools:Dict[str, Any], remainings_args: Iterable[str]) -> List[str]:
  """
  Manually handled arguments to figure which tools are enabled based on flags. 
  """
  remainings_no_dash = [r.replace('-', '') for r in remainings_args]

  enabled_tools: Iterable[str] = [ t for t in remainings_no_dash if t in configured_tools.keys()]
  invalid_tools: Iterable[str]  = [ t for t in remainings_no_dash if t not in configured_tools.keys()]

  # Handle the '--all --no-wpscan' arguments for exemple
  if 'all' in invalid_tools:
    enabled_tools = list(configured_tools)
    invalid_tools.remove('all')
    for i_tool in invalid_tools:
      if i_tool.startswith('no') and i_tool[2:] in enabled_tools:
        enabled_tools.remove(i_tool[2:])
        invalid_tools.remove(i_tool)
  
  if invalid_tools:
      _inv_tools_str = ' '.join([f"--{tool}" for tool in invalid_tools])
      print(f"Invalid tools arguments ignored: {_inv_tools_str}")

  return enabled_tools


def main():
    parser = get_arg_parser()
    args, remainings = parser.parse_known_intermixed_args()

    config = configparser.ConfigParser(comment_prefixes=('#'))
    config.read_dict( {'general': {'title': 'Secuity scans'}} )
    [ config.read(f) for f in args.config ]

    configured_tools: Dict[str, Any] = {section.replace('-', ''):config[section] for section in config if section.startswith("-")}
    
    # Fail fast
    if not configured_tools:
      print("Error: At least one tool must be configured. i.e. :\n[--nikto]\ndescription = Nikto web server scanner\ncommand = nikto -h $url")
      exit(1)
    else:
      print(f"Configured tools: {', '.join(configured_tools.keys())}")

    enabled_tools: List[str] = get_enabled_tools(configured_tools, remainings)

    # Fail fast
    if not enabled_tools:
      print(f"Error: At least one tool must be enable: use --<tool>. i.e.: --{next(iter(configured_tools))}.\n"
        "You can also use --al and -no-<tool> flags. ")
      exit(1)

    else:
      print(f"Enabled tools: {' '.join(enabled_tools) if enabled_tools!=list(configured_tools) else 'all'}")

    # Fail fast
    if not args.url:
      print("Error: No URL supplied, supply URL with --url <url>")
      exit(1)

    mailsender = None
    if 'mail' in config:
      mailsender = MailSender(**config['mail'])

    report_items: Iterable[ReportItem] = list()

    for tool in enabled_tools:
       
        process = Process(  command=configured_tools[tool]['command'].strip(), 
                            popen_args=configured_tools[tool].get('popen_args', '{}') )

        completed_p = process.run(args.url)

        report_items.append(ReportItem( process=completed_p,
                                        description=configured_tools[tool]['description'],
                                        output_files=configured_tools[tool].get('output_files', '').strip().splitlines() ))

    report = Report( items=report_items, title=config['general']['title'], 
                     url=args.url, datetime=datetime.now().isoformat(timespec='seconds') )

    if args.mailto:
      if mailsender:
        print("Sending email report... ")
        mailsender.send(report, args.mailto)
      else:
        print("Not sending email report because no [mail] config is provided. ")
    
    args.output.write(report.as_html())

    print(f"HTML report wrote to: '{args.output.name}'")

    args.output.flush()
    args.output.close()


if __name__ == "__main__":
  main()