# WebMonkeyPatch
Web application MonkeyPatch.  run any web with your login page&amp;logo. Web系统 猴子补丁，主要作用：免密登录第三方web系统，修改logo。我们经常需要使用第三方的web应用，但又不想二次开发修改或者不能修改源码，只需要模拟登录，修改原logo即可。本项目利用同时反向代理原系统和一个微型模拟登录认证系统，使得2个web系统处于符合浏览器同源策略的规则下，通过模拟登录等方式绕过原系统的登录认证，来进行系统封装、二次开发，而不侵入原系统代码
