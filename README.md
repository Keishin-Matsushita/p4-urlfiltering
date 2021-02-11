# p4-urlfiltering　rev0.011
web url filtering by p4 language  
P4言語で実現する url フィルタリング

P4 version 16 SEP 2020.    P4 のバージョンは 2020/09/16 となります。  
Ubuntu 16.04 LTS P4 tutorial VM   P4 チュートリアルで作成する Ubuntu 16.04 LTS VM で動作します。  
VirtualBox VM from https://github.com/p4lang/tutorials  
VM の作成方法は上記 URL を参照してください。  
under run into P4 Development Environment   P4 開発環境の配下で動作します。  
The procedure for installation and running is as follows:   インストールと走行は以下の手順となります。  

```bash
$ cd tutolials/exercises
$ git clone https://github.com/Keishin-Matsushita/p4-urlfiltering.git
$ cd p4-urlfiltering
$ make

```


## Implementing url filtering 

[The topology of the driving environment is as follows.](topology.json)  
走行環境のトポロジーは以下となります。  
run h1 as a web client and h2 and h3 as an http server.  
h1 は Web クライアント、h2,h3 は http server として動作させます。  

                h1 web client
                 |
                 |
               +-+-----------------------+
               | s1 url filtering switch |
               +-+-------+---------------+
                 |       |
                 |       |
                 h2      h3
                http servers


## Step 1: install threading http server (スレッド型 http server のインストール)  
In standard http.server, URL blocking by the s1 switch causes the server to become unresponsive.  
標準の http.server では s1 スイッチによる URL 遮断により、以降 server が応答しなくなります。 

   ```bash
   $ bash ./install.sh
   ```
   ... installed python3 lib ComplexHTTPServer


## Step 2: Run the p4 code `url.p4` (url.p4 を作動させる方法です)

1. In your shell, run:
   シェルで以下のコマンドを打ちます。
   ```bash
   $ make 
   ```

2. You should now see a Mininet command prompt. Try to ping between  
   hosts in the topology:  
   Mininetコマンドプロンプトが表示されます。 ホスト間で ping を実行してみてください。
   ```bash
   mininet> h1 ping h2
   mininet> pingall
   ```

3. Type `xterm` to run the http server.  
   http server を動かすために、xterm を起動します。
   ```bash
   mininet> xterm h2 h3
   ```
   Web Server runs on each terminal as follows.    
   Web Server は各端末で以下のように実行します。
  
   Node:h2
   ```bash
   # python3 -m ComplexHTTPServer 80
   ```

   Node:h3
   ```bash
   # python3 -m ComplexHTTPServer 80
   ```


4. Type `xterm` to run the web client.  
   web client を動かすために、xterm を起動します。
   ```bash
   mininet> xterm h1
   ```

5. Try sending a request from the web client to each server.  
   web client から各サーバにリクエストを送ってみます。  
   
   Node:h1
   ```bash
   # curl http://10.0.0.3/
   hello index 　　　　　　　　　　　　  (response/応答が返ります)
   # curl http://10.0.0.2/
   -- no reply by s1 url filtering　 (s1 url filtering により応答が返りません)
   -- type CTL-C                     (CTL-C を押してコマンドを停止してください)
   # curl http://10.0.0.3/index.html
   -- no reply by s1 url filtering   (s1 url filtering により応答が返りません)
   -- type CTL-C                     (CTL-C を押してコマンドを停止してください)
   # curl http://10.0.0.3/hello.html
   HELLO WORLD! 　　　　　　　　　　　　  (response/応答が返ります)
   # curl http://10.0.0.2/hello.html
   -- no reply by s1 url filtering   (s1 url filtering により応答が返りません)
   -- type CTL-C                     (CTL-C を押してコマンドを停止してください)
   ```

   ```
   factory-setting omitt URL list ( in include/url.p4 )
   工場出荷での URL 遮断リストは以下の通りです。( include/url.p4 にあります )
	  http://10.0.0.2/
	  http://10.0.0.2/hello.html
	  http://10.0.0.3/index.html
   ```


6. Type `exit` to leave each xterm and the Mininet command line.
   Then, to stop mininet:  
   exit を入力して、各 xterm と mininet コマンドラインを終了します。
   ```bash
   mininet> exit
   $ make stop
   ```
   And to delete all pcaps, build files, and logs:  
   pcap、ビルドファイル、ログを削除するには以下のようにします。
   ```bash
   $ make clean
   ```


## Step 3: Edit the filtering URL list (遮断 URL の編集)
   edit URL list and re-run url.p4  
   URLリストを編集してurl.p4を再実行します。
   ```bash
   $ cd include
   $ vi url_exact.py                        // edit exact URL list
   $ python3 url_exact.py > url_exact.p4
   $ vi url_lpm.py                          // edit lpm URL list
   $ python3 url_lpm.py > url_exact.p4
   $ cd ..
   $ make stop; make clean; make      // re-run url.p4
   ```
   :triangular_flag_on_post:  
   URL searches include exact matches(EXACT) and long prefix matches(LPM).    
   'url_exact.py' is generate exactly match url list.  
   'url_lpm.py' is generate longest prefix match url list.  
   URLs that exactly or prefix match this will be dropped.  
   
   URL 検索は完全一致(EXACT)と前方一致(LPM)があります。  
   'url_exact.py' は完全一致 URL リストを作成します。 
   'url_lpm.py' は前方一致 URL リストを作成します。 
   これに完全もしくは前方一致した URL はドロップになります。
   
   - LPM (longest prefix match)  
   A prefix match means that the URI matches all the targets to be searched from the prefix. 
   前方一致とは URI が前方から検索すべき対象にすべて一致することを表します。  
   LPM: http://10.0.0.2/include/  
   http://10.0.0.2/include/   　　　 match(一致)  
   http://10.0.0.2/include/url.p4   match(一致)  
   http://10.0.0.2/include/subdir/  match(一致)  
   http://10.0.0.3/include/   　　　 miss(不一致)  
   http://10.0.0.3/index.html       miss(不一致)  
     
   
## Points to note (留意事項)
- :wastebasket:　~~URL including HTTP COMMAND(GET,POST,HEAD etc.) and HTTP Version(HTTP/1.1 etc.)~~  
  :wastebasket:　~~組み込む URL には HTTP コマンド、バージョンが含まれています。~~  
- URL is URI ( http://10.0.0.1/index.html#1234 : URI = /index.html )  
  URL は URL 中の URI 部分のみとなりました。  
- The part after the hash(#,?) of the URL is ignored by the table search.  
  URL のハッシュ以降の部分は URL 検索からは無視されます。   
- MAX URL Length is 32  
  URL の長さは最大 32 文字です。
- The P4 Table is entered as a constant in the P4 program instead of being submitted from C-Plane  
  P4 Table は C-Plane から投入するのではなく、P4 プログラム内に constant でエントリされてます。
   
## Future tasks (今後の課題)
- [x] Separation of HTTP Command and Version
- [ ] URL length more extension
- [ ] Parsing the true TCP option header instead of using varbit
- [ ] URL Matching with variable url length
- [ ] URL port address supporting 
- [ ] Multi Host IP (Redundant Web server) support
- [ ] Input of match URL Source with P4-Runtime
- [x] Separate support for URL hash tags (#/? etc.)
- [ ] Learning drop url then block all subsequent packets
- [ ] Redirect URL (stepping stone) block
- [x] URL table lpm matching support
- [ ] Send close to server/response HTTP 404 to client with matching block URL

## Revision history  (改定履歴)
- 2021/02/10 Rev0.00 first release
- 2021/02/11 Rev0.01 URL equal URI. URL Hash Tag ignore
- :triangular_flag_on_post:　2021/02/11 Rev0.011 URL lpm(ternary match) support

   
