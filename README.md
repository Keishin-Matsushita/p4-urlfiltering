# p4-urlfiltering
web url filtering by p4 language


# Implementing url filtering 

topology.json

                h1
                 |
                 |
               +-+---------+
               |    s1     |
               +-+-------+-+
                 |       |
                 |       |
                 h2      h3


## Step 1: install threading http server

   ```bash
   $ ./install.sh
   ```
   ... installed python3 lib ComplexHTTPServer


## Step 2: Run the p4 code 'url.p4'

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
   Node:h2
   ```bash
   # python3 -m ComplexHTTPServer 80
   ```

   Node:h3
   ```bash
   # python3 -m ComplexHTTPServer 80
   ```


4. Type `xterm` to invoke client window
   ```bash
   mininet> xterm h1
   ```

5. web client packet send to each web server URL

   Node:h1
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

   factory-setting omitt URL list ( in include/url.p4 )
	  http://10.0.0.2/
	  http://10.0.0.2/hello.html
	  http://10.0.0.3/index.html



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

   editng URL list and re-rune url.p4
   Note: MAX URL Length is 32.

   ```bash
   $ cd include
   $ vi url.py
   // generate omitt URL list
   $ python3 url.py > url.p4
   $ cd ..
   // re-run url.p4
   $ make stop; make clean; make 
   ```

