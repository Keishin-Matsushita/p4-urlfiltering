### p4-urlfiltering
web url filtering by p4 language

P4言語で実現する url フィルタリング


```bash
P4 version 16 SEP 2020.
P4 のバージョンは 2020/08/16 となります。
Ubuntu 16.04 TLS P4 tutorial VM
P4 チュートリアルで作成する Ubuntu 16.04TLS VM で動作します。
VirtualBox VM from https://github.com/p4lang/tutorials
VM の作成方法は上記 URL を参照してください。
under run into P4 Development Environment
P4 開発環境の配下で動作します。
The procedure for installation and running is as follows:
インストールと走行は以下の手順となります。

$ cd tutolials/exercises
$ git clone https://github.com/Keishin-Matsushita/p4-urlfiltering.git
$ cd p4-urlfiltering
$ make

```


## Implementing url filtering 

topology.json
[The topology of the driving environment is as follows.](topology.json)
走行環境のトポロジーは以下となります。
run h1 as a web client and h2 and h3 as an http server.
h1 は Web クライアント、h2,h3 は http server として動作させます。

                h1 web client
                 |
                 |
               +-+------------------------+
               | s1 url filterning switch |
               +-+-------+----------------+
                 |       |
                 |       |
                 h2      h3
                http servers


## Step 1: install threading http server

   ```bash
   $ bash ./install.sh
   ```
   ... installed python3 lib ComplexHTTPServer


## Step 2: Run the p4 code `url.p4`

1. In your shell, run:

   ```bash
   $ make 
   ```

2. You should now see a Mininet command prompt. Try to ping between
   hosts in the topology:
   ```bash
   mininet> h1 ping h2
   mininet> pingall
   ```

3. Type `xterm` to invoke http server
   ```bash
   mininet> xterm h2 h3
   ```
   `Node:h2`
   ```bash
   # python3 -m ComplexHTTPServer 80
   ```

   `Node:h3`
   ```bash
   # python3 -m ComplexHTTPServer 80
   ```


4. Type `xterm` to invoke client window
   ```bash
   mininet> xterm h1
   ```

5. web client packet send to each web server URL

   `Node:h1`
   ```bash
   # curl http://10.0.0.3/
   hello index
   # curl http://10.0.0.2/
   -- no reply by s1 url omitting (filtering)
   -- type CTL-C
   # curl http://10.0.0.3/index.html
   -- no reply by s1 url omitting (filtering)
   -- type CTL-C
   # curl http://10.0.0.3/hello.html
   HELLO WORLD!
   # curl http://10.0.0.2/hello.html
   -- no reply by s1 url omitting (filtering)
   -- type CTL-C
   ```

   ```
   factory-setting omitt URL list ( in include/url.p4 )
	  http://10.0.0.2/
	  http://10.0.0.2/hello.html
	  http://10.0.0.3/index.html
   ```


6. Type `exit` to leave each xterm and the Mininet command line.
   Then, to stop mininet:
   ```bash
   mininet> exit
   $ make stop
   ```
   And to delete all pcaps, build files, and logs:
   ```bash
   $ make clean
   ```


## Step 3: Edit the filtering URL list

   edit URL list and re-rune url.p4

   ```bash
   $ cd include
   $ vi url.py
   // generate omitt URL list
   $ python3 url.py > url.p4
   $ cd ..
   // re-run url.p4
   $ make stop; make clean; make 
   ```
   
   ```
   Note: MAX URL Length is 32.
   ```

