# Secioss CAS(Cloud App Security)
Secioss CAS(Cloud App Security)は、以下の機能を提供するオープンソースのCASBソフトウェアです。
* クラウドサービスのログの収集、可視化
* ネットワーク機器のログから利用しているクラウドサービスを検出
* DLP（Data Loss Prevension)

## 目標
* 可視化、データセキュリティ、コンプライアンス、脅威防御をシンプルな機能として提供
* 海外のCASBサービスでカバーされていない日本のクラウドサービスへの対応
* クラウドサービスがCASBに対応するためのガイドラインやツールの作成
* クラウドサービスに関する情報のデータベース作成
* SASE(Secure Access Service Edge)への対応

## インストール
### 環境
* OS：CentOS 7
* ミドルウェア：Apache、OpenLDAP、PHP、MariaDB

### LISMのインストール
管理コンソールは、LISMパッケージに含まれていますので、まずLISMをインストールして下さい。
LISMのインストールについては、こちら(https://github.com/SeciossOpenSource/LISM)の手順をご覧下さい。

### CASBのインストール

### DLPのインストール
DLPはLISM、CASBとは別のサーバにインストールして下さい。
githubのpackages/secioss-dlp-1.x.x-x.x86_64.tar.gzを展開して、インストールスクリプト(install.sh)を実行して下さい。  
`# ./isntall.sh install`

## 設定
### CASB
### DLP
設定ファイル/usr/share/secioss-dlp/conf/config.iniを環境に合わせて変更して下さい。
```
uri = <LISMのLDAPサーバーのURI>
binddn = <LISMのLDAPサーバーに接続するDN>
bindpw = <LISMのLDAPサーバーに接続するパスワード>
basedn = <LISMのLDAPサーバーのベースDN>
db_host = <DBサーバーのホスト名>
db_user = <DBサーバーに接続するユーザー>
db_password = <DBサーバーに接続するパスワード>
db_name = <データベース名>

[dlp]
class =GCP
credentials = <DLP APIに接続するcredentialファイル>
projectid = <DLP APIに接続するプロジェクトID>
```
