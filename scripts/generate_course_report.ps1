Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression

$templatePath = 'C:\Users\Alitele\Desktop\网络安全实验\26网络安全课程设计报告.docx'
$outputPath = Join-Path (Get-Location) 'Sentinel_Lab_网络安全课程设计报告.docx'
$reportTitle = 'Sentinel Lab Web IDS 与蜜罐演示平台设计与实现'

if (-not (Test-Path -LiteralPath $templatePath)) {
    throw "Template not found: $templatePath"
}

Copy-Item -LiteralPath $templatePath -Destination $outputPath -Force

$zip = [System.IO.Compression.ZipFile]::Open($outputPath, [System.IO.Compression.ZipArchiveMode]::Update)
try {
    $entry = $zip.GetEntry('word/document.xml')
    $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
    $xmlText = $reader.ReadToEnd()
    $reader.Close()
    $entry.Delete()

    [xml]$doc = $xmlText
    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('w', 'http://schemas.openxmlformats.org/wordprocessingml/2006/main')
    $body = $doc.SelectSingleNode('//w:body', $ns)

    function Get-ParagraphText($p) {
        $texts = $p.SelectNodes('.//w:t', $script:ns) | ForEach-Object { $_.'#text' }
        return (($texts -join '')).Trim()
    }

    function Set-ParagraphText($p, $text) {
        $runs = $p.SelectNodes('.//w:r', $script:ns)
        foreach ($run in @($runs)) {
            [void]$run.ParentNode.RemoveChild($run)
        }
        $r = $script:doc.CreateElement('w', 'r', $script:ns.LookupNamespace('w'))
        $t = $script:doc.CreateElement('w', 't', $script:ns.LookupNamespace('w'))
        $t.InnerText = $text
        [void]$r.AppendChild($t)
        [void]$p.AppendChild($r)
    }

    foreach ($p in $doc.SelectNodes('//w:p', $ns)) {
        $text = Get-ParagraphText $p
        if ($text -like '题    目：*') {
            Set-ParagraphText $p "题    目：$reportTitle"
            break
        }
    }

    $removeFrom = $null
    foreach ($child in @($body.ChildNodes)) {
        if ($child.LocalName -eq 'p' -and (Get-ParagraphText $child) -eq '题目') {
            $removeFrom = $child
            break
        }
    }
    if ($null -eq $removeFrom) {
        throw 'Could not find template body marker: 题目'
    }

    $started = $false
    foreach ($child in @($body.ChildNodes)) {
        if ($child -eq $removeFrom) {
            $started = $true
        }
        if ($started -and $child.LocalName -ne 'sectPr') {
            [void]$body.RemoveChild($child)
        }
    }

    $sectPr = $body.SelectSingleNode('w:sectPr', $ns)

    function New-WElement($name) {
        return $script:doc.CreateElement('w', $name, $script:ns.LookupNamespace('w'))
    }

    function Add-TextParagraph($text, $kind = 'body', [bool]$pageBreakBefore = $false) {
        $p = New-WElement 'p'
        $pPr = New-WElement 'pPr'

        if ($pageBreakBefore) {
            $pageBreak = New-WElement 'pageBreakBefore'
            [void]$pPr.AppendChild($pageBreak)
        }

        $jc = New-WElement 'jc'
        $spacing = New-WElement 'spacing'
        [void]$spacing.SetAttribute('line', $script:ns.LookupNamespace('w'), '360')
        [void]$spacing.SetAttribute('lineRule', $script:ns.LookupNamespace('w'), 'auto')
        [void]$pPr.AppendChild($spacing)

        $rPr = New-WElement 'rPr'
        $fonts = New-WElement 'rFonts'
        [void]$fonts.SetAttribute('ascii', $script:ns.LookupNamespace('w'), 'Times New Roman')
        [void]$fonts.SetAttribute('hAnsi', $script:ns.LookupNamespace('w'), 'Times New Roman')
        [void]$fonts.SetAttribute('eastAsia', $script:ns.LookupNamespace('w'), '宋体')
        [void]$rPr.AppendChild($fonts)
        $sz = New-WElement 'sz'
        $szCs = New-WElement 'szCs'

        if ($kind -eq 'title') {
            [void]$jc.SetAttribute('val', $script:ns.LookupNamespace('w'), 'center')
            [void]$pPr.AppendChild($jc)
            $b = New-WElement 'b'
            [void]$rPr.AppendChild($b)
            [void]$sz.SetAttribute('val', $script:ns.LookupNamespace('w'), '32')
            [void]$szCs.SetAttribute('val', $script:ns.LookupNamespace('w'), '32')
        }
        elseif ($kind -eq 'heading') {
            [void]$jc.SetAttribute('val', $script:ns.LookupNamespace('w'), 'both')
            [void]$pPr.AppendChild($jc)
            $b = New-WElement 'b'
            [void]$rPr.AppendChild($b)
            [void]$sz.SetAttribute('val', $script:ns.LookupNamespace('w'), '28')
            [void]$szCs.SetAttribute('val', $script:ns.LookupNamespace('w'), '28')
        }
        elseif ($kind -eq 'subheading') {
            [void]$jc.SetAttribute('val', $script:ns.LookupNamespace('w'), 'both')
            [void]$pPr.AppendChild($jc)
            $b = New-WElement 'b'
            [void]$rPr.AppendChild($b)
            [void]$sz.SetAttribute('val', $script:ns.LookupNamespace('w'), '24')
            [void]$szCs.SetAttribute('val', $script:ns.LookupNamespace('w'), '24')
        }
        elseif ($kind -eq 'placeholder') {
            [void]$jc.SetAttribute('val', $script:ns.LookupNamespace('w'), 'center')
            [void]$pPr.AppendChild($jc)
            $color = New-WElement 'color'
            [void]$color.SetAttribute('val', $script:ns.LookupNamespace('w'), '666666')
            [void]$rPr.AppendChild($color)
            [void]$sz.SetAttribute('val', $script:ns.LookupNamespace('w'), '24')
            [void]$szCs.SetAttribute('val', $script:ns.LookupNamespace('w'), '24')
        }
        else {
            [void]$jc.SetAttribute('val', $script:ns.LookupNamespace('w'), 'both')
            [void]$pPr.AppendChild($jc)
            $firstLine = New-WElement 'ind'
            [void]$firstLine.SetAttribute('firstLineChars', $script:ns.LookupNamespace('w'), '200')
            [void]$pPr.AppendChild($firstLine)
            [void]$sz.SetAttribute('val', $script:ns.LookupNamespace('w'), '24')
            [void]$szCs.SetAttribute('val', $script:ns.LookupNamespace('w'), '24')
        }

        [void]$rPr.AppendChild($sz)
        [void]$rPr.AppendChild($szCs)

        $r = New-WElement 'r'
        [void]$r.AppendChild($rPr)
        $t = New-WElement 't'
        $t.InnerText = $text
        [void]$r.AppendChild($t)
        [void]$p.AppendChild($pPr)
        [void]$p.AppendChild($r)
        [void]$body.InsertBefore($p, $script:sectPr)
    }

    $sections = @(
        @{Kind='title'; Text=$reportTitle; Page=$true},
        @{Kind='heading'; Text='一、设计目的和任务'; Page=$true},
        @{Text='本课程设计围绕 Web 入侵检测与蜜罐诱捕场景展开，目标是设计并实现一个可运行、可演示、可测试的网络安全实验平台。项目命名为 Sentinel Lab，整体采用 Flask + SQLite 技术栈，将公开诱饵页面、请求日志、规则检测、告警生成、自动处置和后台可视化整合在同一个教学系统中。通过该系统，可以观察一次可疑请求从进入 Web 应用开始，到被记录、归一化、检测、形成告警、触发封禁并在后台展示的完整过程。'},
        @{Text='实验任务分为攻击模拟与防御检测两个方面。攻击模拟方面，系统提供搜索、登录、联系表单、敏感路径访问和端口扫描等典型入口，能够演示 SQL 注入、XSS、暴力破解、目录探测和端口扫描等常见攻击行为。防御检测方面，系统需要对这些行为进行结构化记录，按规则或统计特征识别风险，并将结果写入数据库和管理后台。'},
        @{Text='本系统不是生产级 IDS 产品，而是用于课程实践和授权实验环境的安全教学平台。设计时更强调原理可见、链路完整和便于答辩演示：普通访问不会产生告警，异常行为能够在后台形成可解释记录，高危行为可以触发黑名单或应用层端口阻断，从而体现检测与响应的闭环。'},
        @{Text='从课程目标看，本实验需要综合运用网络安全基础知识、Web 攻防原理、数据库持久化、后端编程、前端可视化和测试验证能力。报告中第四部分详细设计步骤只展开 A 同学负责的检测内核、数据底座、后台管理和后台前端实现；公开蜜罐入口、真实抓包链路和部署运维作为项目整体内容在总体设计、环境和测试章节中简要说明。'},
        @{Text='具体任务包括：第一，完成项目需求分析，明确系统需要支持的攻击类型和检测对象；第二，设计总体架构，将 Web 请求链路和端口扫描链路接入统一告警模型；第三，实现检测算法和数据表结构，使攻击事件能够被持久化和查询；第四，实现后台管理页面，支持仪表盘、告警列表、规则管理、系统配置、黑名单和端口阻断管理；第五，设计测试流程，验证各类攻击样例能被识别并能产生预期处置效果。'},

        @{Kind='heading'; Text='二、设计原理'; Page=$true},
        @{Text='Sentinel Lab 的核心原理是将 Web IDS 和蜜罐演示结合起来。蜜罐负责提供对攻击者有吸引力的入口，例如登录页、搜索页、联系表单和常见敏感路径；IDS 负责记录请求、提取特征、执行检测规则并生成告警。两者结合后，系统既能模拟真实攻击面，又能在后台展示检测和处置结果。'},
        @{Text='Web 攻击检测的基本思想是从 HTTP 请求中抽取可疑载荷。SQL 注入通常表现为拼接查询条件、逻辑恒真、联合查询、注释截断等特征；XSS 通常包含 script 标签、事件处理器、危险 URL 或 HTML 注入片段。由于攻击载荷可能出现在 URL 参数、表单字段、JSON 数据或请求路径中，检测前需要把这些内容归并为统一文本，并进行 URL 解码、HTML 实体解码、大小写统一和空白压缩。'},
        @{Text='规则检测采用评分机制。每条规则代表一种攻击特征，可以是关键字匹配，也可以是正则表达式匹配，并带有不同分值。当同一请求命中多条规则且累计分数达到阈值时，系统才生成 SQL 注入或 XSS 告警。这样可以减少单个弱特征造成的误报，也让后台管理员能够通过规则表动态调整检测策略。'},
        @{Text='暴力破解检测属于行为统计检测。它不关注单次请求内容，而关注同一来源 IP 在一段时间窗口内的登录失败次数。如果短时间内失败次数达到低阈值，说明存在异常尝试；达到高阈值则说明风险升级；达到封禁阈值时，系统可以自动加入黑名单。滑动窗口能避免无限累计历史失败次数，使判断更接近实时安全监控。'},
        @{Text='敏感路径扫描检测也属于行为统计检测。扫描器通常会在短时间内访问大量路径，并产生较多 404 响应，同时可能命中 /.env、/phpmyadmin、/wp-admin、/manager/html 等敏感路径。系统综合唯一路径数量、404 次数和敏感路径命中数判断探测行为，避免只因为单个 404 就误报。'},
        @{Text='端口扫描检测基于连接事件。真实演示中，连接事件可由 scapy 抓取入站 TCP SYN 包生成；在检测内核中，系统按来源 IP、目标 IP、协议和时间窗口统计唯一目标端口数量。如果短时间内探测多个不同端口，就形成 port_scan 告警；达到高阈值时联动黑名单和端口阻断。'},
        @{Text='处置机制采用应用层黑名单和端口阻断。黑名单用于阻断某个来源 IP 对公开页面的访问，端口阻断用于演示对指定端口的应用层访问控制。系统不会修改操作系统防火墙规则，因此安全边界清晰，适合课堂演示和课程设计。'},

        @{Kind='heading'; Text='三、实验环境和总体设计'; Page=$true},
        @{Kind='subheading'; Text='3.1 实验环境'},
        @{Text='开发语言和平台为 Python 3、Flask 3、SQLite、Waitress、scapy、HTML、CSS 和 JavaScript。项目在 Windows 环境下开发和演示，局域网测试时可通过 0.0.0.0 监听地址让同网段主机访问。端口扫描抓包实验在 Windows 下需要安装 Npcap，并以管理员权限启动服务。'},
        @{Text='项目依赖通过 requirements.txt 管理，运行前执行 python -m pip install -r requirements.txt 安装依赖。配置文件使用 .env，示例配置由 .env.example 提供。常用配置包括 IDS_HOST、IDS_PORT、IDS_SECRET_KEY、IDS_ADMIN_ALLOWED_IPS、IDS_ADMIN_AUTH_ENABLED、IDS_EXPOSE_LABS、IDS_TRUST_PROXY 和 IDS_PORTSCAN_CAPTURE_ENABLED 等。'},
        @{Text='本地启动方式为 python app.py。app.py 会创建 Flask 应用并打印本机和局域网访问地址，如果安装了 Waitress，则优先使用 Waitress 启动，否则回退到 Flask 内置服务器。部署时也可以通过 wsgi.py 暴露 app 对象，使用 waitress-serve --host=0.0.0.0 --port=5000 wsgi:app 启动。'},
        @{Kind='subheading'; Text='3.2 总体架构'},
        @{Text='系统总体分为公开蜜罐层、检测处理层、数据持久层、后台管理层和运行配置层。公开蜜罐层提供 /、/portal、/search、/contact、/health 以及若干探测路径，用于生成真实请求日志。检测处理层由 detection.py 负责，从日志和连接事件中识别攻击。数据持久层由 SQLite 保存请求日志、连接事件、告警、规则、配置、黑名单、端口阻断和登录尝试。后台管理层提供仪表盘、告警、规则、配置和黑名单页面。运行配置层负责 .env 加载、应用工厂、运行时路径和后台线程状态。'},
        @{Text='系统有两条输入链路。第一条是 Web 请求链路：用户访问公开页面后，请求被记录为结构化 JSON 日志，日志进入 request_logs 表，再触发 SQL 注入、XSS、暴力破解和敏感路径扫描检测，最终生成 attack_events 告警。第二条是端口扫描链路：真实 TCP SYN 抓包事件或测试连接事件进入 connection_events 表，再由端口扫描检测算法统计唯一端口数并生成 port_scan 告警。'},
        @{Text='告警生成后，系统会根据攻击类型、评分、阈值和配置决定是否联动处置。一般告警只写入 attack_events；高危暴力破解、路径扫描或端口扫描可以自动写入 blacklist，并在启用端口阻断时写入 port_blocks。公开请求进入系统时会先检查白名单、黑名单和端口阻断状态，命中封禁时返回阻断页面或 403 JSON。'},
        @{Kind='subheading'; Text='3.3 模块划分'},
        @{Text='ids_app/web.py 是应用工厂，负责初始化数据目录和数据库、加载部署配置、注册公开路由和后台路由，并设置 before_request 与 after_request 钩子。routes_public.py 负责公开蜜罐页面和探测入口。routes_admin.py 负责后台页面、实验动作、统计接口、规则配置、黑名单和 CSV 导出。detection.py 负责请求日志消费、载荷归一化、规则匹配、告警生成、连接事件入库和端口扫描检测。storage.py 负责 SQLite 初始化、默认配置与规则写入、表单校验和安全状态管理。'},
        @{Text='项目结构清晰，便于分工协作。A 同学主要负责 Web 检测主链路、数据库底座和后台管理；B 同学主要负责公开蜜罐入口、端口扫描抓包链路、安全访问控制、部署运行和部分公开前端。报告第四部分将聚焦 A 同学负责内容，体现具体算法和后台实现。'},

        @{Kind='heading'; Text='四、详细设计步骤'; Page=$true},
        @{Kind='subheading'; Text='4.1 A 同学负责范围说明'},
        @{Text='根据分工，A 同学负责检测内核、数据底座、后台管理、后台前端和相关自动化测试。其核心目标是实现系统从请求日志或连接事件到安全告警，再到后台展示和管理的完整链路。该部分主要涉及 ids_app/detection.py、ids_app/storage.py、ids_app/constants.py、ids_app/routes_admin.py、后台模板、static/js/dashboard.js 和 tests/test_app.py。'},
        @{Kind='subheading'; Text='4.2 请求载荷归一化设计'},
        @{Text='检测前首先需要解决输入来源不统一的问题。同一类攻击载荷可能出现在路径、查询参数、表单字段或 JSON 请求体中。如果每个检测器分别处理这些位置，代码会重复且容易漏检。因此在 detection.py 中设计 normalize_payload，将 path、query_params、form_data 和 json_data 合并为统一字符串。'},
        @{Text='归一化后的文本大致形态为：/路径 {查询参数 JSON} {表单数据 JSON} {JSON 数据 JSON}。随后连续进行两次 URL 解码和 HTML 实体解码，再统一转为小写，并将多个空白字符压缩为一个空格。这样，%253Cscript%253E 这类双重编码内容可以被还原为 <script>，&lt;script&gt; 也能被还原，后续规则只需要面对稳定的文本。'},
        @{Text='关键伪代码如下：parts = [path, query_params, form_data, json_data]；combined = join(parts)；重复两次执行 URL 解码和 HTML 实体解码；combined = lower(combined)；combined = compress_space(combined)。该设计减少了检测器之间的重复逻辑，也提高了对编码绕过样例的识别能力。'},
        @{Kind='subheading'; Text='4.3 SQL 注入与 XSS 评分检测'},
        @{Text='SQL 注入与 XSS 检测由 detect_content_attacks 完成。系统先通过 load_enabled_rules 从 rules 表读取启用规则，并按 attack_type 分组。每条规则包含名称、攻击类型、匹配方式、匹配内容、分值和描述。匹配方式支持 keyword 和 regex，regex 会进行防御性执行，坏正则不会导致检测链路崩溃。'},
        @{Text='检测时分别处理 sql_injection 和 xss 两类攻击。对于某一类攻击，系统遍历该类启用规则，如果规则命中归一化文本，就累加 score 并记录规则名称。当累计分数达到系统配置阈值时，系统调用 create_event 写入 attack_events。严重等级根据分数是否明显超过阈值决定，一般为 medium，较高分数为 high。'},
        @{Text='评分模型的优点是可解释、可调整、可扩展。告警摘要会记录命中规则数量和评分，后台可以看到为什么产生告警。管理员可以在规则管理页面新增、修改、启用、停用或删除规则，不需要修改检测代码。相比单个关键字触发告警，评分机制能更好地表达多个弱特征叠加后的风险。'},
        @{Kind='subheading'; Text='4.4 暴力破解滑动窗口检测'},
        @{Text='暴力破解检测由 detect_bruteforce 完成。系统关注的是同一来源 IP 在最近一段时间窗口内的登录失败次数，而不是单次请求内容。每次带有 login_result 的请求都会写入 login_attempts 表，其中 success 字段记录成功或失败，request_path 记录对应路径。'},
        @{Text='当 login_result 为 failure 时，系统以当前记录时间为基准，向前计算 bruteforce_window_minutes 配置的时间窗口，并统计该 IP 在窗口内失败次数。若失败次数低于低危阈值，则不报警；达到低危阈值生成低危或中危告警；达到高危阈值生成高危告警；达到封禁阈值时设置 auto_block，并通过 create_event 联动 block_ip 和 block_port_for_ip。'},
        @{Text='为了避免重复刷屏，检测链路设计了 recent_event_exists 告警冷却。同时，为了不隐藏风险升级，代码中保留了升级例外：如果当前阈值高于最近告警阈值，或者本次从未封禁升级到自动封禁，即使仍处于冷却时间内，也会生成新的告警。这样后台能够看到攻击过程从低危到高危再到封禁的变化。'},
        @{Kind='subheading'; Text='4.5 敏感路径扫描检测'},
        @{Text='敏感路径扫描由 detect_scan 完成。系统先按来源 IP 和 scan_window_minutes 时间窗口读取 request_logs，然后计算三个指标：窗口内访问过的唯一路径数量、状态码为 404 的次数、命中 SENSITIVE_PATH_PATTERNS 的次数。敏感路径包括 /.env、/phpmyadmin、/wp-admin、/manager/html 等典型探测目标。'},
        @{Text='扫描行为的判断采用组合触发方式。若唯一路径数达到 scan_unique_paths_threshold，就说明访问面异常宽；若 404 次数达到 scan_404_threshold，说明存在大量不存在路径探测；若敏感路径命中数达到 scan_sensitive_threshold，则说明探测目标具有明显攻击意图。系统把触发项写入 matched_rules，并根据触发项数量计算分数和严重等级。'},
        @{Text='该设计避免把偶发 404 误判为攻击。只有当短时间内呈现异常访问模式时才会报警，多个指标同时触发时可自动封禁来源 IP。告警摘要中会写明访问了多少个路径、404 次数以及敏感路径探测次数，便于后台分析。'},
        @{Kind='subheading'; Text='4.6 端口扫描检测'},
        @{Text='端口扫描检测由 detect_port_scan 完成。虽然真实抓包入口由其他模块负责，但检测算法和告警生成属于 A 同学负责的检测内核。检测输入是 connection_events 表中的连接事件，每条事件包含来源 IP、目标 IP、目标端口、协议、结果和来源类型。'},
        @{Text='检测时，系统按 source_ip、target_ip、protocol 和 portscan_window_minutes 时间窗口筛选事件，然后统计唯一 target_port 数量。达到 portscan_low_threshold 时生成 medium 告警；达到 portscan_high_threshold 时生成 high 告警并触发自动封禁。告警路径使用 build_port_scan_request_path 生成，例如 tcp://目标IP，便于与 Web 请求路径区分。'},
        @{Text='端口扫描告警会记录 target_ip、unique_ports、port_span 和 source_kind 等信息。这里统计的是唯一端口数量，而不是单纯连接次数，因此可以更准确表达扫描行为。若同一端口被反复访问，不会被误认为端口扫描；只有短时间内探测多个端口才会达到阈值。'},
        @{Kind='subheading'; Text='4.7 告警生成、冷却与自动封禁'},
        @{Text='所有检测器最终都通过 create_event 写入 attack_events。该函数统一处理告警字段，包括 request_log_id、created_at、source_ip、attack_type、severity、score、threshold_value、matched_rules、request_path、summary、blocked 和 auto_blocked。统一入口保证不同攻击类型的告警结构一致，方便后台列表、统计接口和 CSV 导出复用。'},
        @{Text='告警冷却由 recent_event_exists 实现。它按来源 IP、攻击类型、可选请求路径和 alert_cooldown_seconds 查询近期是否已有告警。如果已有同类告警，普通重复触发不会继续写入，避免攻击样例或扫描器造成告警表爆炸。暴力破解、路径扫描和端口扫描在风险升级时会突破冷却限制，以保留关键状态变化。'},
        @{Text='自动封禁通过 create_event 的 auto_block 参数触发。若开启自动封禁，系统调用 block_ip 将来源 IP 加入 blacklist；若 port_block_enabled 开启，则继续调用 block_port_for_ip 为该 IP 增加端口阻断记录。白名单 IP 会被跳过，避免管理员或可信主机在演示过程中被误封。'},
        @{Kind='subheading'; Text='4.8 日志消费与入库主流程'},
        @{Text='Web 请求日志由 consume_pending_logs 消费。该函数记录当前读取偏移量，只处理新增日志行。每行日志按 JSON 解析，解析失败会写入 access.bad.log，避免坏数据静默丢失。结构不完整的记录会抛出 ValueError，也会被隔离到坏日志中。临时性异常不会推进偏移量，便于下次重试。'},
        @{Text='ingest_record 是 Web 请求检测主入口。它先调用 validate_log_record 校验必要字段，再把请求写入 request_logs，并保存 raw_record 和 normalized_payload。入库成功后读取配置，如果来源 IP 在白名单中则跳过检测；如果请求路径是静态资源，也跳过检测以减少噪音。最后依次执行内容攻击、暴力破解和路径扫描检测器。'},
        @{Text='ingest_connection_event 是连接事件检测入口。它先校验连接事件结构，再写入 connection_events。如果来源 IP 不在白名单中，就调用 detect_port_scan。Web 请求链路和连接事件链路最终都汇入 attack_events，使后台可以用统一视角展示不同类型风险。'},
        @{Kind='subheading'; Text='4.9 数据库表结构与默认配置'},
        @{Text='数据层由 storage.py 实现，init_db 原地初始化所有核心表。request_logs 保存 Web 请求日志和归一化载荷；attack_events 保存攻击告警；rules 保存 SQLi/XSS 检测规则；blacklist 保存 IP 黑名单；port_blocks 保存端口阻断；login_attempts 保存登录尝试；connection_events 保存端口探测事件；system_config 保存系统阈值和策略配置。'},
        @{Text='默认配置和规则由 constants.py 维护。DEFAULT_CONFIG 包含 SQLi/XSS 分数阈值、暴力破解窗口和阈值、路径扫描阈值、端口扫描阈值、告警冷却时间、黑名单时长、端口阻断开关、白名单等。CONFIG_SPECS 描述配置项类型和最小值，用于后台表单校验。DEFAULT_RULES 提供内置 SQL 注入和 XSS 规则，使系统启动后无需手动插入规则即可演示。'},
        @{Text='seed_defaults 启动时补齐默认配置和规则。配置通过 INSERT 或 UPDATE 写入 system_config，规则通过名称唯一约束写入 rules。这样既能保证新环境可自举，又能在代码更新规则描述后自动修复说明文字。运行时后台修改的是数据库中的配置值，检测器通过 get_config_map 和 get_int_config 读取。'},
        @{Kind='subheading'; Text='4.10 SQLite 并发与持久化稳定性'},
        @{Text='项目中 Flask 请求线程、日志 watcher 线程和端口扫描抓包线程都可能访问数据库。如果使用 SQLite 默认回滚日志模式，容易在演示时出现 database is locked。为此，connect_db 设置 timeout=30，并执行 PRAGMA journal_mode=WAL、PRAGMA synchronous=NORMAL 和 PRAGMA busy_timeout=30000。'},
        @{Text='WAL 模式允许读写更好地并发推进，busy_timeout 让数据库在锁竞争时等待一段时间，而不是立即失败。虽然 SQLite 仍然不是高并发生产数据库，但对于课程演示场景已经能显著提高稳定性。该设计体现了对运行环境和并发写入问题的考虑。'},
        @{Kind='subheading'; Text='4.11 黑名单、端口阻断和表单校验'},
        @{Text='黑名单和端口阻断由 block_ip、unblock_ip、block_port_for_ip、unblock_port_for_ip 和 cleanup_security_entries 实现。封禁记录包含 source_ip、reason、created_at、expires_at、active 和 created_by。重复封禁会刷新原因和过期时间，过期记录会在状态判断前自动清理。'},
        @{Text='get_enforcement_state 统一返回白名单、黑名单和端口阻断状态，供页面、接口和请求拦截复用。白名单判断通过 system_config 中的 ip_whitelist 进行，白名单 IP 不会被加入黑名单或端口阻断。这样可以保护管理员主机，避免课堂演示时误封控制端。'},
        @{Text='后台表单校验由 validate_config_form 和 validate_rule_form 完成。配置校验会检查整数、布尔值、端口、IP 和 IP 列表格式，并保证暴力破解低阈值不大于高阈值、高阈值不大于封禁阈值，端口扫描低阈值不大于高阈值。规则校验会检查规则名称、攻击类型、匹配方式、分值和正则表达式合法性，防止坏配置进入检测链路。'},
        @{Kind='subheading'; Text='4.12 后台管理路由设计'},
        @{Text='后台管理由 routes_admin.py 实现。/admin/login 提供后台登录，登录前检查管理员 IP 白名单，账号密码正确后写入会话状态。/admin/logout 清除会话。/ops 和 /dashboard 渲染仪表盘页面，展示今日请求、今日告警、活跃黑名单、高危告警和最近告警。'},
        @{Text='/api/stats 是仪表盘核心接口。它聚合最近 24 小时请求数、连接事件数、攻击类型分布、TOP 攻击来源、实时 5 秒粒度流量、近期连接摘要、TOP 连接来源、TOP 目标端口、近期端口扫描告警和抓包状态。接口返回 JSON，由前端定时拉取并更新图表。'},
        @{Text='/alerts 展示最近告警，/export/alerts.csv 导出告警 CSV。CSV 包含 created_at、source_ip、attack_type、severity、score、threshold、request_path 和 summary，便于提交实验结果或后续分析。/rules 支持规则新增、修改、启停和删除。/config 支持系统配置修改和实验记录清空。/blacklist 支持手动封禁、解除封禁、端口阻断和解除端口阻断。'},
        @{Kind='subheading'; Text='4.13 后台前端与可视化'},
        @{Text='后台页面包括 dashboard.html、alerts.html、rules.html、config.html、blacklist.html、admin_login.html 和教学演示首页 index.html。仪表盘页面用于总览系统状态，告警页面用于查看攻击事件，规则页面用于维护 SQLi/XSS 检测规则，配置页面用于调整阈值和策略，黑名单页面用于查看和管理封禁状态。'},
        @{Text='static/js/dashboard.js 负责后台动态图表。它周期性请求 /api/stats，根据返回数据绘制 24 小时趋势、实时流量折线、攻击类型分布、攻击来源排名和端口扫描相关状态。后端负责聚合数据，前端负责可视化展示，两者通过 JSON 接口解耦。'},
        @{Text='前端设计服务于答辩演示：攻击样例提交后，仪表盘统计会变化，告警列表会出现新记录，黑名单页面能看到自动封禁结果。这样的可视化反馈能帮助老师和同学理解检测系统的运行过程，而不需要直接查看数据库。'},
        @{Kind='subheading'; Text='4.14 自动化测试设计'},
        @{Text='A 同学负责的测试覆盖检测算法、后台管理和数据边界。测试包括 SQL 注入、XSS、暴力破解、敏感路径扫描、端口扫描算法回归；规则增删改查和表单校验；系统配置阈值大小关系校验；后台 IP 白名单和登录会话保持；CSV 导出格式；/api/stats 字段结构；历史中文乱码修复回归。'},
        @{Text='这些测试保证核心逻辑不仅在手工演示时有效，也能在后续修改代码后持续回归。特别是检测算法测试，可以验证阈值、冷却、自动封禁和白名单绕过等关键行为，防止修改某个模块时破坏整体链路。'},

        @{Kind='heading'; Text='五、结果测试与分析'; Page=$true},
        @{Text='测试分为自动化测试和手工演示测试两类。自动化测试通过 python -m unittest tests.test_app 运行，覆盖公开页面访问、请求日志写入、SQL 注入、XSS、暴力破解、敏感路径扫描、黑名单、端口阻断、白名单绕过、后台登录、配置表单、规则表单、统计接口、端口扫描抓包解析和中文乱码回归检查。'},
        @{Text='手工测试时先启动服务：python app.py。本机访问 http://127.0.0.1:5000，局域网演示时访问 http://服务器局域网IP:5000。若需要开放后台实验动作，在 .env 中设置 IDS_EXPOSE_LABS=true；若需要验证后台登录，设置 IDS_ADMIN_AUTH_ENABLED=true，并配置管理员用户名和密码。'},
        @{Kind='placeholder'; Text='【截图占位 1：公开蜜罐首页】建议截图内容：浏览器访问 / 页面，展示 Sentinel Lab 公开入口或蜜罐首页。'; Page=$true},
        @{Text='普通访问测试包括 /、/portal、/search?q=test、/contact 和 /health。预期结果是页面或接口正常返回，后台可以看到请求记录，但普通请求不应产生攻击告警。该测试用于确认系统基础路由、日志记录和后台展示正常。'},
        @{Kind='placeholder'; Text='【截图占位 2：SQL 注入告警】建议截图内容：访问 /search?q='' or 1=1 -- 后，在 /alerts 页面出现 SQL 注入告警。'; Page=$true},
        @{Text='SQL 注入测试提交 '' or 1=1 -- 或 union select 1,2。系统会把参数写入请求日志并进行归一化，命中 SQLi 规则后累计评分达到阈值，在 attack_events 中生成 sql_injection 告警。分析结果说明规则评分检测能够识别常见 SQL 注入特征，且告警中包含来源 IP、请求路径、严重等级、分值和摘要。'},
        @{Kind='placeholder'; Text='【截图占位 3：XSS 告警】建议截图内容：在 /contact 表单提交 <script>alert(1)</script> 后，告警列表出现 XSS 记录。'; Page=$true},
        @{Text='XSS 测试提交 <script>alert(1)</script> 或 <img src=x onerror=alert(1)>。系统归一化后识别 script 标签或事件处理器等特征，生成 xss 告警。该结果说明检测器不仅能处理 URL 参数，也能处理表单数据和 HTML 实体编码后的输入。'},
        @{Kind='placeholder'; Text='【截图占位 4：暴力破解封禁】建议截图内容：连续错误登录 /portal 后，/alerts 出现 bruteforce 告警，/blacklist 出现来源 IP。'; Page=$true},
        @{Text='暴力破解测试通过 /portal 连续提交错误密码。低阈值触发后产生 bruteforce 告警，高阈值提高严重等级，达到封禁阈值后来源 IP 进入黑名单。分析结果说明滑动窗口能识别短时间内的连续失败登录，并能根据风险升级触发自动处置。'},
        @{Kind='placeholder'; Text='【截图占位 5：敏感路径扫描告警】建议截图内容：连续访问 /admin、/.env、/phpmyadmin、/wp-admin 后，出现 scan_probe 告警。'; Page=$true},
        @{Text='敏感路径扫描测试连续访问 /admin、/.env、/phpmyadmin、/wp-admin 和 /manager/html。系统在时间窗口内统计唯一路径数、404 次数和敏感路径命中数，达到阈值后生成 scan_probe 告警。该结果说明系统能够根据访问模式识别探测行为，而不是依赖单个请求。'},
        @{Kind='placeholder'; Text='【截图占位 6：端口扫描告警】建议截图内容：另一台主机执行 nmap 扫描后，后台出现 port_scan 告警和连接事件统计。'; Page=$true},
        @{Text='端口扫描测试需要 Windows 安装 Npcap，并在 .env 中开启 IDS_PORTSCAN_CAPTURE_ENABLED=true。从另一台局域网主机执行 nmap 服务器局域网IP。系统从 TCP SYN 包生成 connection_events，唯一目标端口数达到阈值后生成 port_scan 告警，高危扫描可自动加入黑名单并触发端口阻断。该测试验证了连接事件链路与检测内核的整合。'},
        @{Kind='placeholder'; Text='【截图占位 7：仪表盘统计】建议截图内容：/dashboard 页面展示今日请求数、告警数、趋势图、攻击类型分布和抓包状态。'; Page=$true},
        @{Text='仪表盘测试访问 /dashboard 和 /api/stats。预期 JSON 包含 captureStatus、requestsByHour、trafficByHour、trafficRealtime、recentConnectionSummary、topConnectionSources、topTargetPorts、recentPortScanAlerts、attacksByType 和 topAttackIps。前端图表随测试请求增加而刷新，说明后端聚合和前端可视化接口正常。'},
        @{Kind='placeholder'; Text='【截图占位 8：规则、配置和黑名单管理】建议截图内容：/rules、/config、/blacklist 页面展示规则维护、阈值配置和封禁记录。'; Page=$true},
        @{Text='后台管理测试包括规则新增、规则启停、规则删除、配置阈值修改、非法配置拦截、手动加入黑名单、解除封禁和端口阻断管理。预期结果是合法操作写入数据库并产生页面提示，非法 IP、非法端口、坏正则和不合理阈值会被表单校验拦截。该测试说明后台管理功能不仅可展示，还能安全地影响检测链路。'},

        @{Kind='heading'; Text='六、存在的问题'; Page=$true},
        @{Text='第一，系统定位是教学演示平台，不是生产级 IDS。当前规则集和阈值适合课程实验中的典型 payload，但面对真实互联网复杂攻击时，可能存在误报和漏报。后续可以引入更丰富的规则库、异常行为基线和更细粒度的风险评分模型。'},
        @{Text='第二，端口扫描抓包依赖本机权限、Npcap/scapy 和网络环境。在 Windows 中如果没有管理员权限、Npcap 未正确安装、网卡选择不正确或防火墙策略影响流量，抓包结果可能不稳定。后续可以增加抓包环境自检结果在后台页面中的展示，让演示前更容易定位问题。'},
        @{Text='第三，当前端口阻断是应用层阻断演示，不会修改操作系统防火墙。因此它能拦截进入 Flask 应用的请求，但不能真正阻断所有网络层连接。后续如果要扩展为更真实的防御系统，可以设计可选的系统防火墙联动模块，但必须严格限制在授权环境中使用。'},
        @{Text='第四，SQLite 适合轻量级教学项目，但不适合高并发生产场景。虽然系统已启用 WAL 和 busy_timeout，但在大量请求、抓包事件和后台查询同时发生时，仍可能遇到性能瓶颈。后续可以迁移到 PostgreSQL 或 MySQL，并把日志消费改成队列式架构。'},
        @{Text='第五，后台页面目前更偏课程演示，交互已经能完成主要功能，但在可观测性、筛选条件、告警详情、批量操作和审计日志方面仍有提升空间。例如告警列表可以增加时间范围、攻击类型、来源 IP 和严重等级筛选；规则修改可以增加变更记录。'},
        @{Text='第六，当前自动化测试覆盖了核心路径，但仍可以加入更多边界样例，例如双重编码 SQL 注入、混合大小写 XSS、长时间窗口边界、白名单与封禁同时存在、端口阻断过期清理等。测试数据也可以进一步参数化，提高回归测试的覆盖面。'},

        @{Kind='heading'; Text='七、总结'; Page=$true},
        @{Text='本次课程设计完成了一个面向教学演示的 Web IDS 与蜜罐实验平台。系统能够提供公开诱饵入口，记录访问日志和连接事件，通过规则检测和行为统计识别 SQL 注入、XSS、暴力破解、敏感路径扫描和端口扫描，并把结果展示在后台管理页面中。高危行为可以触发黑名单和应用层端口阻断，形成从攻击模拟到检测响应的闭环。'},
        @{Text='在设计过程中，我更加清楚地理解了 IDS 的基本工作方式：单个请求内容适合用规则和特征匹配，连续行为更适合用时间窗口和统计指标判断。SQLi/XSS 检测强调载荷归一化和规则评分，暴力破解和扫描检测强调行为模式，端口扫描检测强调唯一端口数量。不同攻击类型需要不同的检测思路，但最终都应归入统一告警模型。'},
        @{Text='在实现过程中，比较有收获的是把安全检测逻辑和后台管理功能连接起来。检测规则、系统阈值、黑名单和端口阻断都不是孤立代码，而是通过数据库、后台页面和统计接口形成可操作系统。管理员可以查看告警，也可以调整规则和配置，这让课程设计从单纯算法演示变成了完整应用。'},
        @{Text='调试过程中也遇到了一些实际工程问题。例如多线程写 SQLite 可能出现锁竞争，因此需要启用 WAL 和 busy_timeout；攻击载荷可能经过 URL 编码或 HTML 实体编码，因此检测前必须归一化；坏日志不能直接丢弃，否则排查困难，因此需要单独写入 bad log；重复告警会干扰后台观察，因此需要告警冷却和风险升级例外。'},
        @{Text='通过本次实验，我不仅复习了 SQL 注入、XSS、暴力破解、扫描探测等网络安全知识，也提升了 Flask 后端开发、数据库设计、前端可视化和自动化测试能力。后续如果继续改进，可以从规则库完善、检测模型优化、日志队列化、数据库迁移、真实防火墙联动和告警审计等方向展开。'},
        @{Text='总体而言，Sentinel Lab 达到了课程设计目标：它能在授权实验环境中稳定演示常见 Web 攻击和检测响应过程，界面可操作，结果可验证，代码结构清晰，也保留了进一步扩展为更完整安全实验平台的空间。'}
    )

    foreach ($item in $sections) {
        $kind = if ($item.ContainsKey('Kind')) { $item.Kind } else { 'body' }
        $page = if ($item.ContainsKey('Page')) { [bool]$item.Page } else { $false }
        Add-TextParagraph $item.Text $kind $page
    }

    $newEntry = $zip.CreateEntry('word/document.xml')
    $writer = New-Object System.IO.StreamWriter($newEntry.Open(), (New-Object System.Text.UTF8Encoding($false)))
    $writer.Write($doc.OuterXml)
    $writer.Close()
}
finally {
    $zip.Dispose()
}

Write-Output $outputPath




