<?php
$oauth_services = array(
    'box' => array('authorizeurl' => 'https://account.box.com/api/oauth2/authorize', 'tokenurl' => 'https://api.box.com/oauth2/token'),
    'dropbox' => array('authorizeurl' => 'https://www.dropbox.com/oauth2/authorize', 'tokenurl' => 'https://api.dropboxapi.com/oauth2/token'),
    'googleapps' => array('authorizeurl' => 'https://accounts.google.com/o/oauth2/auth?approval_prompt=force&access_type=offline', 'tokenurl' => 'https://accounts.google.com/o/oauth2/token', 'scope' => 'https://www.googleapis.com/auth/drive'),
    'office365' => array('authorizeurl' => 'https://login.microsoftonline.com/%{o}.onmicrosoft.com/oauth2/authorize?resource=https://%{o}-my.sharepoint.com/', 'tokenurl' => 'https://login.microsoftonline.com/%{o}.onmicrosoft.com/oauth2/token'),
);
?>
