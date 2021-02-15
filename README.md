# p4-urlfiltering　rev0.012
web url filtering by p4 language  
P4言語で実現する url フィルタリング

When a client sends an http request to the server, the switch filters and blocks the URL.  
The switch compares and determines the IP address,port and URI, and drops the packet if it becomes a target.    
クライアントからサーバに http リクエストを送った時に、スイッチにより URL をフィルタリングし遮断します。  
スイッチでは IP アドレス、ポートおよび URI を比較し判別、対象となった場合にはパケットをドロップします。  

## Running conditions 動作条件

P4 version 16 SEP 2020.      
Ubuntu 16.04 LTS P4 tutorial VM.   
VirtualBox VM from https://github.com/p4lang/tutorials  
Operates under P4 Behavior Model development environment.  
利用する P4 バージョンは 2020/09/16 となります。  
P4 チュートリアルで作成する Ubuntu 16.04 LTS VM で動作します。   
VM の作成方法は https://github.com/p4lang/tutorials を参照してください。  
P4 Behavior Model 開発環境下で動作します。  
 
## Install インストール方法
1. install threading http server (スレッド型 http server のインストール)  
In standard http.server, URL blocking by the s1 switch causes the server to become unresponsive.  
標準の http.server では s1 スイッチによる URL 遮断により、以降 server が応答しなくなります。 

   ```bash
   $ bash ./install.sh
   ```
   ... installed python3 lib ComplexHTTPServer

2. install p4-urlfiltering (本件のインストール)  
The procedure for installation and running is as follows:  
インストールと走行は以下の手順となります。

   ```bash
   $ cd tutolials/exercises
   $ git clone https://github.com/Keishin-Matsushita/p4-urlfiltering.git
   $ cd p4-urlfiltering
   $ make
   ```

## Specification (仕様)

|Item (項目)                  |Detail (内容)                                          |Remarks (備考) |
|:----------------------------|:-----------------------------------------------------|:-------------|
|Support P4 language (P4 言語) | P4_16 (16 SEP 2020) v1model Behavior Model           |              |
|URL Length Max(最大長)         |256 ascii (256 アスキー文字)                           |Rev0.012      |
|URL Match Kind(検索方式)       |exact (完全一致)</br>lpm (longest prefix match) (前方一致) |Rev 0.011     |
|URL Hash tag support          |Hash Tag(#,?) separation (ハッシュタグ分離)            |Rev 0.010      |
|URL port support (ポート別 URL) |Supports blocking individual ports in URLs          |Rev 0.011     |
|Block URL input(遮断 URL 投入) |In program constant (P4 プログラム内)                  |              |

*Specifications are subject to change without notice.  
仕様は予告なく変更されます。*  


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


## Step 1: Run the p4 code `url.p4` (url.p4 を作動させる方法です)

1. In your shell, run:
   シェルで以下のコマンドを打ちます。
   ```bash
   $ make 
   ```

2. You should now see a Mininet command prompt. Try to ping between hosts in the topology:  
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
   
   # curl http://10.0.0.2/index.html
   -- no reply by s1 url blocking 　 (s1 url blocking により応答が返りません)
   -- type CTL-C                     (CTL-C を押してコマンドを停止してください)
   
   # curl http://10.0.0.3/hello.html
   -- no reply by s1 url blocking 　 (s1 url blocking により応答が返りません)
   -- type CTL-C                     (CTL-C を押してコマンドを停止してください)
   
   # curl http://10.0.0.3/hello2.html
   HELLO WORLD 2! 　　　　　　　　　　　 (response/応答が返ります)
   
   # curl http://10.0.0.2/include/url_lpm.p4
   -- no reply by s1 url blocking 　 (s1 url blocking により応答が返りません)
   -- type CTL-C                     (CTL-C を押してコマンドを停止してください)
   ```

   ```
   factory-setting block URL list ( in include/url_excat.p4,url_lpm.p4 )
   工場出荷での URL 遮断リストは以下の通りです。( include/url_exact.p4,url_lpm.p4 にあります )
	  exact http://10.0.0.2/index.html
	  exact http://10.0.0.3/hello.html
	  lpm   http://10.0.0.2/include/
	  lpm   http://10.0.0.2/set/
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


## Step 2: Edit the filtering URL list (遮断 URL の編集)
   edit URL list and re-run url.p4  
   URLリストを編集してurl.p4を再実行します。
   ```bash
   $ cd include
   $ vi url.py                        // edit block URL list
   $ python3 url.py                   // generate P4 URL Tables
   $ cd ..
   $ make stop; make clean; make      // re-run url.p4
   ```
   :triangular_flag_on_post:  See [url.py](include/url.py) for more details.  
   URL searches include exact matches(EXACT) and long prefix matches(LPM).    
   `url.py` is generate exactly,lpm match url list and check IP Address and TCP ports list.  
   The URL determined by this will be a drop.  
   
   詳細は [url.py](include/url.py) を参照してください。  
   URL 検索は完全一致(EXACT)と前方一致(LPM)があります。  
   `url.py` は完全一致、前方一致 URL リスト、及び裁可する IP アドレス、TCP ポートのリストを作成します。   
   これにより判定された URL はドロップになります。 
   
   - LPM (longest prefix match)  
   A prefix match means that the URI matches all the targets to be searched from the prefix.   
   前方一致とは URI が前方から検索すべき対象にすべて一致することを表します。    
   LPM: http://10.0.0.2/include  
   http://10.0.0.2/include/　　　　　　match(一致)  
   http://10.0.0.2/include/url.p4　　match(一致)  
   http://10.0.0.2/include/subdir/　　match(一致)  
   http://10.0.0.3/include/　　　　　　miss(不一致)  
   http://10.0.0.2/index.html　　　　　miss(不一致)  
    
## Points to note (留意事項)
- :wastebasket:　~~URL including HTTP COMMAND(GET,POST,HEAD etc.) and HTTP Version(HTTP/1.1 etc.)~~  
  :wastebasket:　~~組み込む URL には HTTP コマンド、バージョンが含まれています。~~  
- It is the IP address TCP port and the URI part in the URL that are determined by the URL.  
  ( http://10.0.0.1:8000/index.html#1234 : URI = /index.html )  
  URL で判別するのは IP アドレス TCP ポート及び URL 中の URI 部分となりました。  
- The part after the hash(#,?) of the URL is ignored by the table search.  
  URL のハッシュ以降の部分は URL 検索からは無視されます。   
- MAX URL Length is 256  
  URL の長さは最大 256 文字です。
- The URL Table is entered as a constant in the P4 program instead of being submitted from C-Plane  
  URL Table は C-Plane から投入するのではなく、P4 プログラム内に constant でエントリされてます。
   
## Issues to be solved (解決した課題)
- [x] *Separation of HTTP Command and Version*
- [x] *Separate support for URL hash tags (#/? etc.)*
- [x] *URL table lpm matching support*
- [x] *URL port address supporting* 

## Future tasks (今後の課題)
- [ ] URL length more extension
- [ ] Multi Host IP (Redundant Web server) support
- [ ] Input of match URL Source with P4-Runtime
- [ ] Found drop url then block all subsequent packets
- [ ] Send close to server/response HTTP 404 to client with matching block URL

## Revision history  (改定履歴)
- 2021/02/10 Rev0.000 first release
- 2021/02/11 Rev0.010 URL equal URI. URL Hash Tag ignore
- 2021/02/11 Rev0.011 URL lpm match, URL port support
- :triangular_flag_on_post:　2021/02/15 Rev0.012 URL length 32→256 extent

   
