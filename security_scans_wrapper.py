#!/usr/bin/env python3
"""
Generic wrapper for any tools that runs on a given URL. 
Generates a HTML document and can send reports by email. 
Secuity scans are the main usage. 
"""

import os
import sys
from typing import Optional, Sequence, Dict, Any, Iterable, List
import smtplib
import json
import argparse
import configparser
import functools
import pathlib
import io
import re
import glob
import shlex
import tempfile
import string
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText

import invoke
import attr
import markdown
from ansi2html import Ansi2HTMLConverter
ansi2HTMLconverter = Ansi2HTMLConverter(inline=True, linkify=True)

print = functools.partial(print, file=sys.stderr)

# stolen
STYLE =   """<style>

/* Admonitions */

div.admonition p.admonition-title:after {
    content: ":";
}

div.admonition p.admonition-title {
    margin: 0;
    font-weight: bold;
}

div.admonition p.admonition-title {
    color: #333333;
}

div.admonition {
    padding: 3px;
    margin-bottom: 20px;
    background-color: #EEE;
    border: 1px solid #CCC;
    border-radius: 4px;
}

div.warning, div.attention, div.danger, div.error, div.caution {
    background-color: #ffcf9cb0;
    border: 1px solid #ffbbaa;
}

div.danger p.admonition-title, div.error p.admonition-title, div.caution p.admonition-title {
    color: #b94a48;
}

div.tip p.admonition-title, div.hint p.admonition-title, div.important p.admonition-title{
    color: #3a87ad;
}

div.tip, div.hint, div.important {
    background-color: #d9edf7;
    border-color: #bce8f1;
}
  </style>
  """

def parse_timedelta(time_str: str) -> timedelta:
    """
    Parse a time string e.g. (2h13m) into a timedelta object.  Stolen on the web
    """
    regex = re.compile(
        r"^((?P<days>[\.\d]+?)d)?((?P<hours>[\.\d]+?)h)?((?P<minutes>[\.\d]+?)m)?((?P<seconds>[\.\d]+?)s)?$"
    )
    parts = regex.match(time_str)
    if parts is None:
        raise ValueError(
            f"Could not parse any time information from '{time_str}'.  Examples of valid strings: '8h', '2d8h5m20s', '2m4s'"
        )
    time_params = {
        name: float(param) for name, param in parts.groupdict().items() if param
    }
    return timedelta(**time_params)  # type: ignore [arg-type]

def get_valid_filename(s: str) -> str:
    '''Return the given string converted to a string that can be used for a clean filename.  Stolen from Django I think'''
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)

def error(msg: str) -> None:
    print(f"ERROR: {msg}")
    sys.exit(1)

@attr.s(auto_attribs=True)
class ProcessResult:
  stdout: str
  stderr: str
  command: str # not the actual command
  returncode: Optional[int] = 0
  failure: Optional[str] = None

def _parse_timedelta_seconds(string: str) -> int:
    return int(parse_timedelta(string).total_seconds())

@attr.s(auto_attribs=True)
class Process:
  """
  Run arbitrary commands with subprocess from string command with string interpolations and popen args as JSON. 
  """
  command: str # not the actual command
  real_command: str # the "real" command, one that will be run by invoke.run()
  timeout: int
 
  @classmethod
  def new(cls, command: str, interpolations: Dict[str, str], timeout: str) -> 'Process': 
    """Create a new process with the given interpolation parameters."""
    # substitute interpolations
    cmd = cls._interpolate_real(command, **interpolations)
    
    # fail if missing place holders
    cls._check_interpolation_leftovers(cmd)

    return cls(command=cls._interpolate_no_values(command, **interpolations), 
              real_command=cmd, timeout=_parse_timedelta_seconds(timeout))

  @staticmethod
  def _interpolate_real(cmd: str, **kwargs: Any) -> str:
    for k,v in kwargs.items():
      if '{{%s}}'%k in cmd:
        cmd = cmd.replace('{{%s}}'%k, shlex.quote(v))
    return cmd

  @staticmethod
  def _interpolate_no_values(cmd: str, **kwargs: Any) -> str:
    for k,v in kwargs.items():
      if k == 'url':
        if '{{%s}}'%k in cmd:
          cmd = cmd.replace('{{%s}}'%k, shlex.quote(v))
      else:
        if '{{%s}}'%k in cmd:
          # Do not show values of interpolation place holder except url. 
          cmd = cmd.replace('{{%s}}'%k, '***')
    return cmd
  
  @staticmethod
  def _check_interpolation_leftovers(cmd: str) -> None:
    placeholder_regex = re.compile(r'{{((?:}(?!})|[^}])*)}}')
    all_leftovers_placeholder = placeholder_regex.findall(cmd)
    if all_leftovers_placeholder:
      error("the following place holders could not get interpolated: " 
        f"{', '.join(all_leftovers_placeholder)}. Use --arg KEY=VALUE to pass values.")

  def run(self) -> ProcessResult:
    """Run the process."""
    
    # The actual command
    print(f"Running: '{self.real_command}'")

    try:
      result = invoke.run(command=self.real_command, timeout=self.timeout, pty=True, out_stream=sys.stderr)
      return ProcessResult(stdout=result.stdout, stderr=result.stderr, command=self.command)

    except invoke.exceptions.CommandTimedOut as err:
      return ProcessResult(stdout=err.result.stdout, stderr=err.result.stderr, command=self.command, 
          returncode=None, failure=f"Command timed out after {self.timeout} seconds. Configure 'scan_timeout' to allow more time.")

    except invoke.exceptions.UnexpectedExit as err:
      return ProcessResult(stdout=err.result.stdout, stderr=err.result.stderr, command=self.command, 
          returncode=err.result.exited, 
          failure=f"Command encountered a bad exit code: {err.result.exited}.")

def _glob_filepaths(files: List[str]) -> List[pathlib.Path]:
    # find output files with globbing if any
    globbed = list()
    for f in files:
      found_files = glob.glob(f)
      if not found_files:
        print(f"No file found at path '{f}'")
      else:
        globbed.extend(found_files)

    paths = [ pathlib.Path(f) for f in globbed  ]
    file_paths: List[pathlib.Path] = []
    for path in paths:
      if path.exists():
        if path.is_file():
          file_paths.append(path)
    if file_paths:
      print(f"Output file(s): {', '.join(f.as_posix() for f in file_paths)}")
    return file_paths

@attr.s(auto_attribs=True, frozen=True)
class ReportItem:
    """
    Transform a process ProcessResult object to pseudo markdown/HTML.

    Strore output files as Path. 
    """

    process: ProcessResult
    description: str  

    process_output_html: str
    """
    Process stdout encoded as HTML, truncated if full_process_output_file is not None. 
    """
    
    output_files: List[pathlib.Path] = attr.ib(factory=list)
    """
    Generated output files.
    """

    full_process_output_html_file: Optional[pathlib.Path] = None
    """
    This is used to store the full output when it must be truncated. None if stdout is small enough. 
    """

    @classmethod
    def new(cls, process: ProcessResult,  truncate_output: int, description: str, output_files: List[str]) -> 'ReportItem':
      
      ansi_result = process.stdout or '' + process.stderr or ''

      process_output_html: str
      full_process_output_html_file: Optional[pathlib.Path] = None

      # Truncate output if need be.
      if len(ansi_result) > truncate_output:
        process_output_html = ansi2HTMLconverter.convert(ansi_result[:truncate_output], full=False)
        full_process_output_html = ansi2HTMLconverter.convert(ansi_result, full=True)
        full_process_output_html_file = pathlib.Path(tempfile.gettempdir() + os.sep + 
            'security-scans-wrapper-temp' + os.sep + get_valid_filename(description) + '.txt')
        os.makedirs(full_process_output_html_file.parent, exist_ok=True)
        if full_process_output_html_file.exists():
              os.remove(full_process_output_html_file)
        with full_process_output_html_file.open('w', encoding='utf-8') as f:
          f.write(full_process_output_html)
      
      else:
        process_output_html = ansi2HTMLconverter.convert(ansi_result, full=False)
      
      return ReportItem(process=process, description=description, output_files=_glob_filepaths(output_files), 
                        process_output_html=process_output_html, 
                        full_process_output_html_file=full_process_output_html_file)
    
    def as_markdown(self) -> str:
      output_filenames = (f"`{f.name}`" for f in self.output_files)
      output_files = "" if not self.output_files else f"""!!! note "Output file{'s' if len(self.output_files) >= 2 else ''} attached"\n    {', '.join(output_filenames)}"""
      failure_infos = f"""!!! error\n    {self.process.failure}""" if self.process.failure else ''
      truncate_infos = f"""!!! warning\n    The output has been truncated, please refer to the attached file `{self.full_process_output_html_file.name}` to review the full log.""" if self.full_process_output_html_file else ''
      
      command = self.process.command.replace('\n', '<br />')
      
      return f"""
## {self.description}

<strong>Command</strong> <br />

<code>
{command}
</code>

<strong>Result</strong> <br />

{failure_infos}

{truncate_infos}

{output_files}

<strong>Output</strong> <br />

<div class="body_foreground body_background" style="font-size: 10;" >
<pre class="ansi2html-content">

{self.process_output_html}

</pre>
</div>

"""


@attr.s(auto_attribs=True, frozen=True)
class Report:
  """
  Transform a collection of ReportItem into a HTML document. 
  """

  items: Iterable[ReportItem]
  title: str
  url: str
  datetime: str

  def _as_markdown(self) -> str:
    md = f"# {self.title} - {self.url} - {self.datetime}\n"
    md += "[TOC]\n"
    for item in self.items:
      md += f"{item.as_markdown()}"
    return md

  def as_html(self) -> str:
    html = markdown.markdown(self._as_markdown(), 
      extensions=['pymdownx.highlight', 'pymdownx.superfences', 
                  'pymdownx.details', 'pymdownx.magiclink', 
                  'markdown.extensions.toc', 'markdown.extensions.admonition'])
    return string.Template("""<!DOCTYPE html>
<html>
<head>

  $ansi_headers

  $style

</head>
<body>
  <div class="container">

    $html

  </div>
</body>
</html>
""").substitute(ansi_headers=ansi2HTMLconverter.produce_headers(), style=STYLE, html=html)


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
          files = item.output_files
          # Add the extra output file if the log is big.
          if item.full_process_output_html_file:
                files.insert(0, item.full_process_output_html_file)
          for f in files:
            # Read the output
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
    parser.add_argument('--config', '-c', metavar="PATH", help="Configuration file(s).", action="extend", nargs="+", required=True)
    parser.add_argument('--url', '-u', metavar="URL", help="URL to scan.")
    parser.add_argument('--arg', '-a', metavar="KEY=VALUE", help="Extra interpolation arguments", action="extend", nargs="+", default=[])
    parser.add_argument('--mailto', '-m', metavar="EMAIL", help="Send report by email to recipient(s).", action="extend", nargs="+")
    parser.add_argument('--output', '-o', metavar="PATH", help="Save report to HTML file. Default to report.html", 
                        default='report.html', type=argparse.FileType('w', encoding='utf-8'))
    return  parser

def get_extra_arguments(raw_extra_args: List[str]) -> Dict[str, str]:
  extra_args = {}
  for arg in raw_extra_args:
    parsed = arg.split("=", 1)
    if len(parsed) != 2:
      error(f"cannot parse interpolation argument: '{arg}'. Should be like 'KEY=VALUE'")
    key, value = parsed
    extra_args[key] = value
  return extra_args

def get_enabled_tools(configured_tools:Dict[str, Any], remainings_args: Iterable[str]) -> Sequence[str]:
  """
  Manually handled arguments to figure which tools are enabled based on flags. 
  """
  remainings_no_dash = [r.replace('-', '') for r in remainings_args]

  enabled_tools: List[str] = [ t for t in remainings_no_dash if t in configured_tools.keys()]
  invalid_tools: List[str]  = [ t for t in remainings_no_dash if t not in configured_tools.keys()]

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


def main() -> None:
    parser = get_arg_parser()
    args, remainings = parser.parse_known_intermixed_args()

    config = configparser.ConfigParser(comment_prefixes=('#'))
    config.read_dict( {'general': {'title': 'Secuity scans'}} )
    [ config.read(f) for f in args.config ]

    configured_tools: Dict[str, Any] = {section.replace('-', ''):config[section] for section in config if section.startswith("-")}
    
    # Fail fast
    if not configured_tools:
      error("at least one tool must be configured. i.e. :\n[--nikto]\ndescription = Nikto web server scanner\ncommand = nikto -h $url")
    else:
      print(f"Configured tools: {', '.join(configured_tools.keys())}")

    # Fail fast
    if not args.url:
      error("no URL supplied, supply URL with --url <url>")

    enabled_tools: Sequence[str] = get_enabled_tools(configured_tools, remainings)

    # Fail fast
    if not enabled_tools:
      error(f"at least one tool must be enable: use --<tool>. i.e.: --{next(iter(configured_tools))}.\n"
        "You can also use --al and --no-<tool> flags. ")

    else:
      print(f"Enabled tools: {' '.join(enabled_tools) if enabled_tools!=list(configured_tools) else 'all'}")

    mailsender = None
    if 'mail' in config:
      mailsender = MailSender(**config['mail'])

    report_items: List[ReportItem] = []

    extra_args = get_extra_arguments(args.arg)

    process_tools_map: Dict[str, Process] = {}

    for tool in enabled_tools:
       
        process = Process.new(command=configured_tools[tool]['command'].strip(), 
                              interpolations=dict(url=args.url, **extra_args),
                              timeout=config['general'].get('scan_timeout', '24h'),)

        process_tools_map[tool] = process
    
    for tool_name, process in process_tools_map.items():
        
        if process:
          
          process_result = process.run()
        
          report_items.append(ReportItem.new( process=process_result, 
                                          truncate_output=int(config['general'].get('truncate_output', '10000')),
                                          description=configured_tools[tool_name].get('description', 'Security scans'),
                                          output_files=configured_tools[tool_name].get('output_files', '').strip().splitlines() ))

    report = Report( items=report_items, title=config['general']['title'], 
                     url=args.url, datetime=datetime.now().isoformat(timespec='seconds') )

    if args.mailto:
      if mailsender:
        tos: List[str] = []
        for mail in args.mailto:
          tos.extend(mail.split(','))
        print("Sending email report... ")
        mailsender.send(report, tos)
      else:
        print("Not sending email report because no [mail] config is provided. ")
    
    args.output.write(report.as_html())

    print(f"HTML report wrote to: '{args.output.name}'")

    # Cleanup temp files
    for item in report.items:
      if item.full_process_output_html_file:
        try:
          os.remove(item.full_process_output_html_file)
        except IOError: 
          pass

    exit(0)

if __name__ == "__main__":
  main()
