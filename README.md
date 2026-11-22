# 安全外链生成（Host Header 注入修复）

渗透测试发现：找回密码邮件中的重置链接取自请求的 `Host` 头，攻击者篡改请求头即可让
邮件里的链接指向自己的域名，受害者点击后重置令牌外泄。同类问题影响所有"根据请求信息
拼接对外链接"的功能：密码重置、邮箱验证、邀请、分享。

本模块是修复的参考实现 + 安全回归测试，核心原则：

> **对外链接里的 host/scheme/port/basePath 永远来自服务端配置；请求数据只能在
> 配置好的站点白名单里"选择一个"，永远不能"引入一个"。**

## 设计

```
RequestView（框架无关的请求视图）
        │
        ▼
PublicOriginResolver ──► 只在可信代理（CIDR 白名单）后才读 X-Forwarded-Host/Proto
        │                HostNormalizer 规范化（小写、punycode、去端口/尾点、
        │                拒绝 userinfo/路径/反斜杠）后作为白名单查找键
        │                匹配不到 → 默认站点（fail-closed）
        ▼
PublicOrigin（scheme + Site，Site 含 canonicalHost/basePath/port/locales）
        │
        ▼
LinkBuilder ──► locale 白名单校验、路径段/query 百分号编码
        │
        ▼
OutboundLinkService ──► passwordResetLink / emailVerificationLink /
                        invitationLink / shareLink 全部走这一个入口
```

关键类：

| 类 | 职责 |
|---|---|
| `PublicUrlConfig` / `Site` | 每个环境的合法域名、别名、语言、basePath、端口、可信代理 CIDR |
| `TrustedProxyMatcher` | IPv4/IPv6 CIDR 匹配，空列表 = 不信任任何代理（安全默认） |
| `HostNormalizer` | Host 值规范化与拒绝（`@` userinfo 欺骗、路径、非法端口、裸 IPv6…） |
| `PublicOriginResolver` | 把请求解析成一个可信 origin；任何异常输入都回落到默认站点 |
| `LinkBuilder` / `OutboundLinkService` | 唯一的对外链接出口，统一编码与 locale 处理 |

## 在真实代码库里排查（审计清单）

凡是下列模式出现在"生成发给用户的链接"的代码路径上，都是可疑点：

```bash
grep -rnE 'getRequestURL|getRequestURI|getServerName|getServerPort|getScheme\(\)' --include='*.java' .
grep -rnE 'getHeader\(\s*"(Host|host|X-Forwarded-[^"]*)"' --include='*.java' .
grep -rnE 'X-Forwarded-(Host|Proto|Prefix|Port)|ForwardedHeaderFilter|RemoteIpValve' -r .
grep -rnE 'ServletUriComponentsBuilder|fromCurrentRequest|fromRequest\(|MvcUriComponentsBuilder' --include='*.java' .
grep -rnE 'UriComponentsBuilder.*(host|scheme)\(' --include='*.java' .
```

再顺着邮件/短信发送点（`JavaMailSender`、`MailService`、模板里的 `${resetUrl}` 等）
反向找 URL 是在哪里拼的。每一处都改成调用 `OutboundLinkService`。

## 框架与代理配合

- **Tomcat**：如用 `RemoteIpValve`，`trustedProxies` 必须只列自己的 LB/代理网段；
  它只影响 `request.getRemoteAddr()` 等，本模块不依赖它，双保险。
- **Spring**：`ForwardedHeaderFilter` 会让 `ServletUriComponentsBuilder` 采信
  `X-Forwarded-*`——只有在网关已剥离客户端伪造头的前提下才能开。本模块不依赖它。
- **网关节点**：最外层代理应 `proxy_set_header Host $host;`（或显式白名单），并按
  链路透传 `X-Forwarded-Host`；内层服务把外层代理网段配进 `trustedProxies`。
- 多级代理下站点挂在子路径（如 `https://admin.example.com/console`）时，把前缀配在
  `Site.basePath`，不要信 `X-Forwarded-Prefix`。

## 各环境配置示例

```java
PublicUrlConfig config = PublicUrlConfig.builder()
    .site(Site.builder("main")
        .host("example.com").host("www.example.com")
        .defaultLocale("zh").supportedLocale("en").supportedLocale("ja")
        .build())
    .site(Site.builder("admin")
        .host("admin.example.com")
        .defaultLocale("zh")
        .basePath("/console")          // 多级代理暴露的子路径
        .build())
    .site(Site.builder("staging")
        .host("staging.internal.example")
        .defaultLocale("zh")
        .port(8443)                    // 非标准端口来自配置，不来自请求
        .build())
    .defaultSite("main")               // 任何识别不了的 Host 都回落到这里
    .trustedProxies(List.of("10.0.0.0/8", "2001:db8::/32"))
    .httpsOnly(true)
    .build();
```

每个环境（dev/staging/prod）用各自的配置文件生成这个对象即可，链接行为一致。

## 测试

```bash
gradle test
```

51 个测试覆盖：Host 头篡改（攻击域名、后缀相似域名、`@` userinfo、端口注入、
大小写/尾点、Unicode 形似字符、缺失 Host）、`X-Forwarded-Host/Proto`（可信/不可信
来源、逗号链、空值、非 http(s) scheme）、多域名/多语言选择、IDN punycode、
basePath 与非标准端口、token/邀请 id/分享 id 的编码逃逸，以及渗透测试原始场景的
端到端回归（令牌永远不会落到配置外域名）。
