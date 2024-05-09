# llm-security-quickstart
## 20240509
截至2024年，Langchain框架已经被发现存在多个安全漏洞，这些漏洞被分配了不同的CVE编号。以下是一些详细的漏洞描述：

1. **CVE-2023-29374**
   - **漏洞描述**：这是一个任意代码执行漏洞，影响使用0.0.131及之前版本的Langchain，并调用Langchain LLMMathChain链的程序。此漏洞允许攻击者执行任意命令，可能导致系统安全受到严重威胁[1][3].

2. **CVE-2024-28088**
   - **漏洞描述**：这是一个目录遍历漏洞，存在于Langchain 0.1.10及以下版本。攻击者可以通过控制`load_chain`调用路径参数的最后一部分来遍历`../`目录，绕过预期的加载配置行为。此漏洞可以被用来泄露在线大型语言模型服务的API密钥或实现远程代码执行[2][5][18].

3. **CVE-2024-27444**
   - **漏洞描述**：这是一个代码注入漏洞，影响Langchain Experimental。在`pal_chain/base.py`中未禁止对特定Python属性的访问，如`__import__`、`__subclasses__`等，攻击者可以通过这些属性绕过CVE-2023-44467的修复

Citations:
[1] https://www.secrss.com/articles/59635
[2] https://avd.aliyun.com/detail?id=AVD-2024-28088
[3] https://cloud.tencent.com/developer/article/2357773
[4] https://developers.gmo.jp/38381/
[5] https://zhi.oscs1024.com/42702.html
[6] https://note.com/ppi_motoki/n/n01ba11add9dc
[7] https://www.elastic.co/cn/blog/privacy-first-ai-search-langchain-elasticsearch
[8] https://zhi.oscs1024.com/42449.html
[9] https://vuldb.com/zh/
[10] https://github.com/chinesehuazhou/python-weekly/blob/main/docs/2024-01-13-weekly.md
[11] https://yylives.cc/2024/04/02/cve-2024-3094-newly-discovered-backdoor-in-xz-tools/
[12] https://vuldb.com/ja/
[13] https://help.aliyun.com/zh/emr/emr-on-ecs/product-overview/vulnerability-notice-upgrade-solr-to-fix-vulnerabilities
[14] https://blog.csdn.net/2401_84411822/article/details/137891009
[15] https://www.youxia.org
[16] https://m.freebuf.com/articles/neopoints/398298.html
[17] https://note.com/neco_s/n/n7b054f2cc507
[18] http://www.nsfocus.net/vulndb/93102
[19] https://zhi.oscs1024.com/41856.html
[20] https://avd.aliyun.com/detail?id=AVD-2024-3571


---------

在2024年，LlamaIndex被报告有以下几个CVE漏洞：

1. **CVE-2024-23751**: 这是一个SQL注入漏洞，影响了LlamaIndex项目。这种类型的漏洞允许攻击者通过执行恶意SQL命令来操纵或访问数据库中的数据，这可能导致数据泄露或损坏[5][11]。

2. **CVE-2024-3098**: 这是一个特权提升漏洞，影响了LlamaIndex中的`exec_utils`函数。通过这个漏洞，攻击者可以通过篡改未知的值来提升权限，从而可能获得更高的系统访问权限[6]。

这些漏洞的存在表明LlamaIndex在数据安全和访问控制方面存在缺陷，需要及时的修复和更新以防止潜在的安全风险。

Citations:
[1] https://www.cnblogs.com/LittleHann/p/17879401.html
[2] https://www.secrss.com/articles/59635
[3] https://note.com/ippei_suzuki_us/n/n8f5c31246a61
[4] https://github.com/taishi-i/awesome-ChatGPT-repositories/blob/main/docs/README.zh-hant.md
[5] https://zhi.oscs1024.com/41856.html
[6] https://vuldb.com/ja/
[7] https://juejin.cn/map-post-202403-125
[8] https://www.tincheung.com/news/list?page=43
[9] https://finance.sina.cn/2024-03-19/detail-inanweur7031546.d.html?node_id=76524&oid=como+ganhar+dinheiro+-+perda+de+m%C3%A3o+%3E%3E+%28bet5g.+xyz%29+%28bet5g.+xyz%29&vt=4
[10] https://juejin.cn/map-post-202401-161
[11] https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-001713.html
[12] https://www.ipa.go.jp/security/security-alert/2024/0410-ms.html
[13] https://japansecuritysummit.org/2024/05/9490/
[14] https://m.freebuf.com/articles/neopoints/398298.html

