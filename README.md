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

### CASBのインストール
CASBはLISMと同じサーバーにインストールして下さい。
githubのpackages/secioss-auditlog-1.x.x-x.x86_64.tar.gzを展開して、インストールスクリプト(install.sh)を実行して下さい。  
`# ./isntall.sh install`

### DLPのインストール
DLPはLISM、CASBとは別のサーバにインストールして下さい。
githubのpackages/secioss-dlp-1.x.x-x.x86_64.tar.gzを展開して、インストールスクリプト(install.sh)を実行して下さい。  
`# ./isntall.sh install`

### データベースのインストール
DLPの検出情報を登録するデータベースを作成します。MariaDBをインストールして、データベースdlpに以下のテーブルを作成して下さい。
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

### DLP
DLPの検査は以下のコマンドを実行して下さい。
```
# php /usr/share/secioss-dlp/bin/dlp_check.php
```
検査結果は、LISMの管理コンソールの[DLP]-[機密データ検出]から確認することができます。
