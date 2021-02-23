#!/usr/bin/env python3
"""
Generic wrapper for any tools that runs on a given URL. 
Generates a HTML document and can send reports by email. 
Secuity scans are the main usage. 
"""

import sys
import subprocess
from typing import Sequence, TYPE_CHECKING, Dict, Any, Iterable, List, Optional, Tuple, Callable, NoReturn
import smtplib
import json
import argparse
import configparser
import functools
import pathlib
import io
import os
import re
import signal
import glob
import shlex
import queue
import threading
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText

import attr
import markdown
from ansi2html import Ansi2HTMLConverter
ansi2HTMLconverter = Ansi2HTMLConverter(inline=True, linkify=True)

print = functools.partial(print, file=sys.stderr)

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

def func_timeout(
    timeout: float,
    func: Callable[..., Any],
    args: Tuple[Any, ...] = (),
    kwargs: Dict[str, Any] = {},
    ) -> Any:
    """Run func with the given timeout.
    :raise TimeoutError: If func didn't finish running within the given timeout.
    """

    class FuncThread(threading.Thread):
        def __init__(self, bucket: queue.Queue) -> None:  # type: ignore [type-arg]
            threading.Thread.__init__(self)
            self.result: Any = None
            self.bucket: queue.Queue = bucket  # type: ignore [type-arg]
            self.err: Optional[Exception] = None
            self.daemon = True # die when the main thread dies

        def run(self) -> None:
            try:
                self.result = func(*args, **kwargs)
            except Exception as err:
                self.bucket.put(sys.exc_info())
                self.err = err

    bucket: queue.Queue = queue.Queue()  # type: ignore [type-arg]
    it = FuncThread(bucket)
    it.start()
    it.join(timeout)
    if it.is_alive():
        raise TimeoutError()
    else:
        try:
            _, _, exc_trace = bucket.get(block=False)
        except queue.Empty:
            return it.result
        else:
            raise it.err.with_traceback(exc_trace)  # type: ignore [union-attr]

def error(msg: str) -> NoReturn:
    print(f"ERROR: {msg}")
    exit(1)

@attr.s(auto_attribs=True)
class Process:
  """
  Run arbitrary commands with subprocess from string command with string interpolations and popen args as JSON. 
  """
  command: str = attr.ib() # not the actual command
  popen: subprocess.Popen = attr.ib()
  timeout: int = attr.ib(converter=lambda x: parse_timedelta(x).total_seconds())
  popen_args: Dict[str, Any] = attr.ib(factory=list)
 
  @classmethod
  def new(cls, command: str, interpolations: Dict[str, str], 
          timeout: str, popen_args: Dict[str, Any]):
    
    """Create a new process with the given interpolation parameters."""
    # substitute interpolations
    cmd = cls._interpolate_real(command, **interpolations)
    
    # fail if missing place holders
    cls._check_interpolation_leftovers(cmd)

    is_shell = popen_args.get('shell', False)
    
    # cast command to right format depending shell = True
    _cmd = shlex.split(cmd) if not is_shell else cmd
    
    if is_shell:
      # https://stackoverflow.com/questions/4789837/how-to-terminate-a-python-subprocess-launched-with-shell-true
      popen_args.update(dict(preexec_fn=os.setsid))
    
    popen = subprocess.Popen(
      _cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen_args)

    return cls(command=cls._interpolate_no_values(command, **interpolations), 
               popen=popen, timeout=timeout, popen_args=popen_args)

  @staticmethod
  def _interpolate_real(cmd: str, **kwargs) -> str:
    for k,v in kwargs.items():
      if '{{%s}}'%k in cmd:
        cmd = cmd.replace('{{%s}}'%k, shlex.quote(v))
    return cmd

  @staticmethod
  def _interpolate_no_values(cmd: str, **kwargs) -> str:
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

  def kill(self) -> None:
    """Kill the process"""
    assert self.popen is not None
    if self.popen_args.get('shell', False):
      os.kill(os.getpgid(self.popen.pid), signal.SIGKILL)
    else:
      os.kill(self.popen.pid, signal.SIGKILL)

  def run(self) -> subprocess.CompletedProcess:
    """Run the process."""
    
    # the actual command
    print(f"Running: '{self.popen.args}'\n(Popen arguments: {self.popen_args})")

    try:
      stdout, stderr = func_timeout(timeout=self.timeout, func=self.popen.communicate)
    except TimeoutError:
      self.kill()
      print(f"Timeout reached after {self.timeout} seconds for process {self.popen.pid} while running: '{self.popen.args}'")
      stdout, stderr = f"The command timed out after {self.timeout} seconds. Configure 'scan_timeout' to allow more time.", ""
    except KeyboardInterrupt:
      self.kill()
      raise

    return subprocess.CompletedProcess(
        args = self.command, 
        returncode = self.popen.returncode, 
        stdout = stdout, 
        stderr = stderr)

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
    Transform a process CompletedProcess object to pseudo markdown/HTML.

    Strore output files as Path. 
    """

    process: subprocess.CompletedProcess
    description: str  
    output_files: List[pathlib.Path] = attr.ib(factory=list, converter=_glob_filepaths)
    
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


def main():
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

    enabled_tools: List[str] = get_enabled_tools(configured_tools, remainings)

    # Fail fast
    if not enabled_tools:
      error(f"at least one tool must be enable: use --<tool>. i.e.: --{next(iter(configured_tools))}.\n"
        "You can also use --al and --no-<tool> flags. ")

    else:
      print(f"Enabled tools: {' '.join(enabled_tools) if enabled_tools!=list(configured_tools) else 'all'}")

    mailsender = None
    if 'mail' in config:
      mailsender = MailSender(**config['mail'])

    report_items: Iterable[ReportItem] = list()

    extra_args = get_extra_arguments(args.arg)

    processes: List[Process] = []

    for tool in enabled_tools:
       
        process = Process.new(command=configured_tools[tool]['command'].strip(), 
                              interpolations=dict(url=args.url, **extra_args),
                              timeout=config['general'].get('scan_timeout', '4h'),
                              popen_args=json.loads(configured_tools[tool].get('popen_args', '{}')))

        processes.append(process)
    
    for process in processes:

        completed_p = process.run()
      
        report_items.append(ReportItem( process=completed_p,
                                        description=configured_tools[tool].get('description', 'Security scans'),
                                        output_files=configured_tools[tool].get('output_files', '').strip().splitlines() ))

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

    exit(0)

if __name__ == "__main__":
  main()