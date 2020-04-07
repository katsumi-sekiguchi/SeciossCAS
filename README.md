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
LISMのインストールについては、こちら( https://github.com/SeciossOpenSource/LISM )の手順をご覧下さい。
インストール後、/usr/share/seciossadmin/etc/secioss-ini.phpの/* CASB ... */で囲まれた個所のコメントアウトを外して下さい。

### CASBのインストール
CASBはLISMと同じサーバーにインストールして下さい。
githubのpackages/secioss-auditlog-1.x.x-x.x86_64.tar.gzを展開して、インストールスクリプト(install.sh)を実行して下さい。  
`# ./isntall.sh install`

### DLPのインストール
DLPはLISM、CASBとは別のサーバにインストールして下さい。
githubのpackages/secioss-dlp-1.x.x-x.x86_64.tar.gzを展開して、インストールスクリプト(install.sh)を実行して下さい。  
`# ./isntall.sh install`

### データベースのインストール
アクティビティログのグラフ用の情報を登録するデータベースを作成します。MariaDBをインストールしてデータベースreportに以下のテーブルを作成して下さい。
~~~
CREATE TABLE IF NOT EXISTS activity_info (
      tenant varchar(64) NOT NULL,
      date datetime NOT NULL,
      service varchar(129) NOT NULL,
      activity varchar(32) NOT NULL,
      country_code varchar(3) NOT NULL,
      domain varchar(64) NOT NULL,
      longitude varchar(10) DEFAULT NULL,
      latitude varchar(10) DEFAULT NULL,
      number int(10) DEFAULT NULL,
      PRIMARY KEY (tenant,date,service,activity,country_code,domain)
)
~~~      
DLPの検出情報を登録するデータベースを作成します。データベースdlpに以下のテーブルを作成して下さい。
~~~
CREATE TABLE `dlp_alert` (
  `datetime` char(19) DEFAULT NULL,
  `tenant` varchar(80) DEFAULT NULL,
  `uid` varchar(130) DEFAULT NULL,
  `service` varchar(64) DEFAULT NULL,
  `file` varchar(255) DEFAULT NULL,
  `msg` text
)
~~~

## 設定
### CASB
CASBでは、管理コンソールで設定した各クラウドサービスのAPI接続情報を使用してアクティビティログを収集します。
設定ファイル/opt/secioss/etc/service_auditlog.confを環境に合わせて変更して下さい。
```
ldap_uri = <LISMのLDAPサーバーのURI>
ldap_user = <LISMのLDAPサーバーに接続するDN>
ldap_password = <LISMのLDAPサーバーに接続するパスワード>
ldap_basedn = <LISMのLDAPサーバーのベースDN>

elasticsearch_url  = <アクティビティログ保管用ElasticsearchサーバーのURL>

decrypt_key = "/opt/secioss/etc/auth_tkt.conf"
```
次に、/opt/secioss/etc/auth_tkt.confのTKTAuthSecretの値をランダムな文字列に書き換えて下さい。

### DLP
DLPでは、Google Cloud PlatformのDLP APIを使用します。
設定ファイル/usr/share/secioss-dlp/conf/config.iniを環境に合わせて変更して下さい。
```
uri = <LISMのLDAPサーバーのURI>
binddn = <LISMのLDAPサーバーに接続するDN>
bindpw = <LISMのLDAPサーバーに接続するパスワード>
basedn = <LISMのLDAPサーバーのベースDN>
keyfile = /usr/share/secioss-dlp/conf/auth_tkt.conf
db_host = <DBサーバーのホスト名>
db_user = <DBサーバーに接続するユーザー>
db_password = <DBサーバーに接続するパスワード>
db_name = dlp

[dlp]
class =GCP
credentials = <DLP APIに接続するcredentialファイル>
projectid = <DLP APIに接続するプロジェクトID>
```
/usr/share/secioss-dlp/conf/auth_tkt.confのTKTAuthSecretにCASBの/opt/secioss/etc/auth_tkt.confに設定した値と同じ値を設定して下さい。

## クラウドサービスの設定
LISMの管理コンソールからCASBの対象とするクラウドサービスの設定を行います。
### CASB
[CASB]-[クラウドサービス]-[一覧]で[登録]タブに移動してクラウドサービスを選択して、クラウドサービスに接続するための設定を行います。
クラウドサービスの設定が完了したら、定期的にクラウドサービスのアクティビティログを取得します。
#### Amazon Web Service
APIにアクセスするAWSのIAMユーザーの設定を行います。
* アクセスキー：IAMユーザーのアクセスキー
* シークレットキー：IAMユーザーのシークレットキー
#### Box
JWT認証でAPIにアクセスするカスタムアプリの設定を行います。
* クライアントID：アプリのクライアントID
* クライアントシークレット：アプリのクライアントシークレット
#### Dropbox
APIにアクセスするDropboxのアプリの設定を行います。
* アクセストークン：APIにアクセスするアクセストークン
#### Google
APIにアクセスするプロジェクトのサービスアカウントの設定を行います。
* クライアントID：サービスアカウントのクライアントID
* メールアドレス：サービスアカウントのメールアドレス
* 秘密鍵：サービスアカウントの秘密鍵
#### LINE WORKS
APIの設定を行います。
* Tenant ID：Tenant ID
* Domain ID：Domain ID
* Consumer Key：Server API Consumer KeyのConsumer Key
* Token：Server ListのToken
#### Office365
APIにアクセスするAzureアプリの設定を行います。
* アプリケーションID：アプリのアプリケーションID
* アプリケーションキー：アプリのアプリケーションキー
* ディレクトリーID：アプリのディレクトリーID
#### Salesforce
APIの設定を行います。
* ドメイン：Salesforceのドメイン
* クライアントID：APIのクライアントID
* クライアントシークレット：APIのクライアントシークレット
* 管理者名：Salesforceの管理者名
* 管理者パスワード：Salesforceの管理者パスワード
* セキュリティトークン：Salesfoceの管理者セキュリティトークン
### DLP
[DLP]-[ストレージ]-[一覧]からクラウドストレージを選択して、ストレージに接続するための設定を行います。
クラウドストレージの設定が完了したら、[設定]で検査するストレージを選択して下さい。
#### Amazon S3
APIにアクセスするAWSのIAMユーザーの設定を行います。
* アクセスキー：IAMユーザーのアクセスキー
* シークレットキー：IAMユーザーのシークレットキー
* リージョン：検査するS3のリージョン
* バケット：検査するS3のバケット名
#### Box
JWT認証でAPIにアクセスするカスタムアプリの設定を行います。
* クライアントID：アプリのクライアントID
* クライアントシークレット：アプリのクライアントシークレット
* エンタープライズID：BoxのエンタープライズID
* 公開鍵ID：JWT認証の公開鍵ID
* 秘密鍵：JWT認証の秘密鍵
* パスフレーズ：秘密鍵のパスフレーズ
#### Dropbox
APIにアクセスするDropboxのアプリの設定を行います。
* アクセストークン：APIにアクセスするアクセストークン
#### Google Drive
APIにアクセスするGCPのサービスアカウントの設定を行います。
* クライアントID：サービスアカウントのクライアントID
* メールアドレス：サービスアカウントのメールアドレス
* 秘密鍵：サービスアカウントの秘密鍵
#### OneDrive
APIにアクセスするAzureアプリの設定を行います。
* ドメイン：OneDriveのドメイン
* クライアントID：アプリのクライアントID
* クライアントシークレット：アプリのクライアントシークレット

## 実行
### CASB
アクティビティログは以下のコマンドが定期的に実行され取得します。
```
# /opt/secioss/sbin/service_auditlog.pl
```
### DLP
DLPの検査は以下のコマンドを実行して下さい。
```
# php /usr/share/secioss-dlp/bin/dlp_check.php
```
検査結果は、LISMの管理コンソールの[DLP]-[機密データ検出]から確認することができます。
