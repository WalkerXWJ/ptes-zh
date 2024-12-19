# ptes-zh

PTES Chinese Translation

- 此项目是对[pentest-standard](http://www.pentest-standard.org)的翻译，将英文内容翻译为了中文。PTES渗透测试执行标准，原文文档的最后更新时间在2012年4月份，显有些陈旧了，比如，文档中对Kali Linux的描述还停留在Back Track的称呼。但文档的参考价值依旧很大。因为地域文化、行业标准、法律法规差异的问题，文档的很多内容都不能搬过来直接使用，需要使用当前区域的替代方法。在学习文档内容的同时，你需要知道，无论何时如果你进行未授权的渗透测试和网络攻击都会给你带来麻烦，即使在授权的测试中，也要注意测试的授权范围；否则未授权的行为，可能给你带来无尽的麻烦，包括导致你承担经济赔偿，甚至是失去人身自由。遵守你所在地区的法律要求，是你首先要考虑的事情。
- 版本：v1.0
- 在后续 [Releases](https://github.com/WalkerXWJ/ptes-zh/releases)中会提供以下中文文件：
  - 适用PTES规范的渗透测试报告模版文件《PTES渗透测试报告模版.docx》；
  - 适用于国内标准规范的渗透测试报告模版文件《渗透测试报告报告模版.docx》；
  - PTES渗透测试执行标准中文版《PTES渗透测试执行标准中文版.pdf》；

本项目仅用于技术性研究使用，请勿用于其他用途。

# 主页

## PTES标准的整体结构

        <span style="color: blue">渗透测试执行标准由七个主要部分组成。</span> 这些部分涵盖了渗透测试的各个方面——从初步沟通和测试理由，到情报收集与威胁建模阶段，此时测试人员在幕后工作，以深入了解被测试的组织；接着是漏洞分析、漏洞利用和后期利用阶段，在这些阶段中，测试人员的技术专长与业务理解相结合；最后是报告阶段，以一种对客户有意义并提供最大价值的方式记录整个过程。

        当前版本被视为v1.0，因为标准的核心要素已经确定，并在业内经过一年多的实践。v2.0正在筹备中，将在“级别”方面提供更细致的划分，即渗透测试各个元素可以执行的不同强度级别。因为每次渗透测试各不相同，从常规的网络应用或网络测试，到全面的红队模拟，这些级别将帮助组织定义对手可能展现的复杂程度，并让测试人员在最需要的领域增强测试强度。在情报收集部分可以看到关于“级别”的初步探索。

        以下是标准定义的渗透测试执行的主要部分：

1. [预接触活动](./main-page/pre-engagement.md)
2. [情报收集](./main-page/Intelligence_Gathering.md)
3. [威胁建模](./main-page/Threat_Modeling.md)
4. [漏洞分析](./Vulnerabliity_Analysis.md)
5. [漏洞利用](./Exploitation.md)
6. [后期利用]()
7. [报告]()

        由于标准没有提供实际渗透测试的技术指南，我们还创建了技术指南来补充标准。可以通过以下链接访问技术指南：

    [技术指南](./ptes_technical_guidelines/PTES_Technical_Guidelines.md）

有关此标准的更多信息，请访问：

渗透测试执行标准：常见问题解答
