<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SWOT_SCAN</title>
    <style>
    body {
        font-family: Arial, sans-serif;
        margin: 20px;
        padding-top: 50px; /* Сдвигаем всё вниз на 50px */
        background-color: black;
        color: white;
        display: flex;
        flex-direction: column; /* Теперь блоки будут вертикально центрированы */
        align-items: center;   /* Центрируем контейнер по горизонтали */
    }

    .input-box {
        width: 100%;
        text-align: center;
        margin-bottom: 30px;
    }

    input[type="text"] {
        padding: 10px;
        width: 300px;
        border-radius: 5px;
        border: none;
        font-size: 16px;
        text-align: center;
    }

    button {
        padding: 10px 20px;
        background-color: #902537;
        border: none;
        color: white;
        font-weight: bold;
        border-radius: 5px;
        cursor: pointer;
        font-size: 16px;
        margin-top: 10px;
    }

    button:hover {
        background-color: #902537;
    }

    .container {
        max-width: 1000px;
        width: 100%;
        background-color: gray;
        border: 2px solid white;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        border-radius: 10px;
        padding: 20px;
        box-sizing: border-box;
        position: relative;
        margin: 0 auto 40px auto; /* Центрируем контейнер */
    }

    .results {
        margin-top: 20px;
        padding: 15px;
        border: 1px solid #ccc;
        background-color: #1a1a1a;
        word-break: break-all;
        white-space: pre-wrap;
        color: #ccc;
    }

    .copy-button {
        position: absolute;
        top: 10px;
        right: 10px;
        padding: 5px 10px;
        background-color: #902537;
        color: white;
        border: none;
        cursor: pointer;
        border-radius: 5px;
    }

    .copy-button:hover {
        background-color: #902537;
        border-radius: 10px;
    }
    
    .hidden-url {
    display: none; /* Скрываем элементы */
}

#show-all-urls {
    margin-top: 10px;
    padding: 10px 20px;
    background-color: #902537;
    border: none;
    color: white;
    font-weight: bold;
    cursor: pointer;
    border-radius: 5px;
}

#show-all-urls:hover {
    background-color: #902537;
}
    
    
</style>
</head>
<body>


<h1 styel="color:white; text-align:center;">Average scan time 40 minutes</h1>

<!-- Глобальное поле ввода -->
<div class="input-box">
    <h2 style="color:white;">Enter domain:</h2>
    <form method="POST" action="">
        <input type="text" name="global_domain" placeholder="example.com" required style="width:300px; padding:10px;"><br>
        <button type="submit" name="run_all_scans">Start Scan</button>
    </form>
</div>

<?php
// Получаем домен из формы или сохраняем в куки
$domain = '';
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['global_domain'])) {
    $domain = filter_input(INPUT_POST, 'global_domain', FILTER_SANITIZE_URL);
}

// Функция для фильтрации nslookup вывода
function filterNslookupOutput($output) {
    $removeLines = ['unknown query type: ALL', 'Server:', 'Non-authoritative answer:'];
    $lines = explode("\n", $output);
    $filtered = array_filter($lines, function($line) use ($removeLines) {
        foreach ($removeLines as $rl) {
            if (stripos($line, $rl) !== false) return false;
        }
        return true;
    });
    return trim(implode("\n", $filtered));
}

// Функция для поиска поддоменов
function scanSubdomains($domain) {
    $subdomains = [
        "ftp", "ssh", "mail", "www", "api", "dev", "test", "blog", "cms", "cdn", "db", "admin", "backup", "beta",
        "demo", "docs", "download", "forum", "help", "intranet", "jobs", "lab", "live", "login", "m", "mobile",
        "monitor", "news", "old", "partner", "pay", "payment", "portal", "preview", "prod", "qa", "secure", "shop",
        "staging", "static", "status", "support", "sys", "test2", "training", "uat", "upload", "user", "vpn", "web",
        "wiki", "wp", "www2", "www3", "www4", "vpn", "dev", "test", "staging", "stage", "uat", "beta", "prod",
    "production", "api", "api2", "admin", "portal", "intranet", "login", "auth", "sso", "dashboard", "secure",
    "cdn", "static", "img", "assets", "files", "downloads", "docs", "docs-old", "support", "help", "status",
    "monitor", "monitoring", "metrics", "grafana", "prometheus", "zabbix", "alerts", "log", "logs", "elk",
    "kibana", "splunk", "jira", "confluence", "wiki", "git", "gitlab", "repo", "ci", "jenkins", "build", "pipeline",
    "internal", "private", "mysql", "db", "sql", "mssql", "pgsql", "mongodb", "db01", "db1", "database",
    "backup", "backups", "archive", "old", "oldsite", "legacy", "legacy-app", "fileserver", "storage", "vault",
    "email", "smtp", "imap", "mx1", "mx2", "mail01", "mail1", "webmail1", "outlook", "owa", "exchange", "calendar",
    "chat", "teams", "slack", "meet", "video", "zoom", "calls", "phone", "voip", "softphone", "crm", "erp",
    "sap", "salesforce", "billing", "invoice", "payments", "pay", "shop", "store", "checkout", "cart", "customer",
    "account", "accounts", "user", "users", "client", "clients", "partner", "partners", "b2b", "b2c", "marketing",
    "ads", "campaign", "track", "tracking", "redirect", "go", "link", "newsletter", "emailing", "register", "signup",
    "signin", "login2", "auth1", "oauth", "saml", "devops", "tools", "tooling", "cloud", "cloud01", "azure",
    "aws", "s3", "bucket", "cdn1", "gcp", "compute", "k8s", "kubernetes", "node1", "nodes", "app", "apps", "app1",
    "frontend", "fe", "backend", "be", "web", "web01", "web1", "web2", "webapp", "webadmin", "cms", "wordpress",
    "wp", "drupal", "joomla", "adminer", "phpmyadmin", "pma", "sqladmin", "search", "blog", "news", "press",
    "media", "images", "img1", "cdn-assets", "static1", "static2", "video1", "live", "stream", "events", "event",
    "register-event", "labs", "research", "lab", "testenv", "dev1", "dev2", "test1", "qa", "qa1", "qa2", "bug",
    "bugs", "issue", "feedback", "review", "reviews", "preview", "preview1", "preview2", "demo", "demo1",
    "sandbox", "training", "elearning", "learn", "edu", "docs2", "docs3", "howto", "guides", "manual", "fileshare",
    "share", "sharepoint", "storage1", "cdn2", "cdn3", "metrics2", "perf", "performance", "securelogin", "identity",
    "idp", "keycloak", "vault1", "vault2", "token", "secrets", "devtools", "developer", "developers", "developer1",
    "monitor1", "ops", "noc", "netops", "secops", "soc", "security", "siem", "audit", "compliance", "legal",
    "hr", "finance", "legal-docs", "payroll", "careers", "jobs", "job", "apply", "onboarding", "offboarding",
    "sourcing", "travel", "fleet", "vehicle", "facilities", "office1", "branch1", "hq", "dc1", "datacenter",
    "edge", "router", "switch", "firewall", "waf", "antiddos", "vpn1", "vpn2", "vpn-gw", "proxy", "squid",
    "cache", "internalapi", "customerapi", "partnerapi", "b2b-api", "b2c-api", "staff", "staffportal",
    "employee", "employees", "adminportal", "superadmin", "superuser", "root", "console", "remote1", "rdp",
    "jump", "bastion", "jumpbox", "ts", "rdgw", "gateway", "fw", "loadbalancer", "lb", "lb01", "cdn-cache",
    "api-gateway", "webgateway", "authproxy", "ssh", "ssh1", "dns", "ns1", "ns2", "ntp", "time", "geo", "location",
    "iot", "device", "devices", "sensor", "sensors", "control", "controller", "admin1", "login-panel", "staff-login" 
    ];

    $results = [];

    foreach ($subdomains as $sub) {
        $fullDomain = "$sub.$domain";
        try {
            $output = shell_exec("nslookup -query=ALL " . escapeshellarg($fullDomain));
            if (strpos($output, "NXDOMAIN") === false && strpos($output, "SERVFAIL") === false) {
                $filteredOutput = filterNslookupOutput($output);
                if (!empty(trim($filteredOutput))) {
                    $results[] = "<b>$fullDomain</b><br><pre>" . htmlspecialchars($filteredOutput) . "</pre>";
                }
            }
        } catch (Exception $e) {}
    }

    return !empty($results) ? implode("<br>", $results) : "Nothing found.";
}

// Функция WhatWeb
function runWhatWeb($domain) {
    $output = shell_exec("whatweb " . escapeshellarg($domain));
    return !empty(trim($output)) ? "<pre>" . htmlspecialchars($output) . "</pre>" : "Nothing found.";
}

function getWaybackUrls($domain) {
    $wayback_url = "https://web.archive.org/cdx/search/cdx?url={$domain}/*&output=json&fl=original&collapse=urlkey";
    $response = @file_get_contents($wayback_url);
    $urls = json_decode($response, true);

    if (!empty($urls)) {
        $result = "<ul>";
        foreach ($urls as $index => $url) {
            $urlLink = htmlspecialchars($url[0]);
            // Первые 50 результатов видны, остальные скрыты
            $class = ($index >= 50) ? " class='hidden-url'" : "";
            $result .= "<li$class><a href='$urlLink' target='_blank'>$urlLink</a></li>";
        }
        $result .= "</ul>";

        // Добавляем кнопку "Показать все"
        if (count($urls) > 50) {
            $result .= "<button id='show-all-urls'>Показать все результаты</button>";
        }

        return $result;
    } else {
        return "Nothing found.";
    }
}

// Функция Directory Check
function checkDirectories($domain) {
    $directories = [
    		    "/sub",
                    "/payment",
                    "/price",
                    "/about",
                    "/contact",
                    "/blog",
                    "/shop",
                    "/cart",
                    "/checkout",
                    "/login",
                    "/register",
                    "/robots.txt",
                    "/admin",
    "/admin.php",
    "/administrator",
    "/administrator.php",
    "/admin/login",
    "/admin/dashboard",
    "/admin/settings",
    "/admin/users",
    "/admin/panel",
    "/admin_area",
    "/admin_console",
    "/admin_login",
    "/dashboard",
    "/control",
    "/controlpanel",
    "/cpanel",
    "/moderator",
    "/root",
    "/superadmin",
    "/system",
    "/system_admin",
    "/secure",
    "/secure_admin",
    "/manage",
    "/management",
    "/login",
    "/login.php",
    "/auth",
    "/auth.php",
    "/signin",
    "/signup",
    "/register",
    "/logout",
    "/password_reset",
    "/forgot-password",
    "/account",
    "/accounts",
    "/user",
    "/users",
    "/profile",
    "/members",
    "/clients",
    "/customer",
    "/customers",
    "/config",
    "/config.php",
    "/config.inc.php",
    "/configuration.php",
    "/.env",
    "/settings",
    "/setup",
    "/setup.php",
    "/install",
    "/install.php",
    "/upgrade",
    "/update",
    "/database",
    "/database.php",
    "/db",
    "/dbadmin",
    "/dbadmin.php",
    "/phpmyadmin",
    "/phpmyadmin.php",
    "/mysql",
    "/mysql.php",
    "/sql",
    "/sql.php",
    "/db_backup",
    "/backup",
    "/backup.sql",
    "/dump.sql",
    "/wp-admin",
    "/wp-login.php",
    "/wp-content",
    "/wp-includes",
    "/wp-config.php",
    "/wp-json",
    "/wp-cron.php",
    "/wp-uploads",
    "/joomla",
    "/joomla-admin",
    "/drupal",
    "/magento",
    "/prestashop",
    "/logs",
    "/logs.php",
    "/log",
    "/error",
    "/error.php",
    "/errors",
    "/debug",
    "/debug.php",
    "/server-status",
    "/server-info",
    "/crash",
    "/stacktrace",
    "/cgi-bin",
    "/cgi-bin/test.cgi",
    "/cgi-bin/admin.cgi",
    "/cgi-bin/login.cgi",
    "/shell",
    "/shell.php",
    "/cmd",
    "/cmd.php",
    "/console",
    "/console.php",
    "/terminal",
    "/bash",
    "/bash.php",
    "/sh",
    "/sh.php",
    "/old",
    "/old_site",
    "/backup_old",
    "/backups",
    "/bak",
    "/bak.php",
    "/site_old",
    "/archive",
    "/archives",
    "/admin_old",
    "/admin_bak",
    "/db_old",
    "/database_old",
    "/config_old",
    "/api",
    "/api.php",
    "/graphql",
    "/graphql.php",
    "/mail",
    "/mail.php",
    "/webmail",
    "/email",
    "/newsletter",
    "/subscribe",
    "/unsubscribe",
    "/sms",
    "/webhook",
    "/json",
    "/xml",
    "/shop",
    "/store",
    "/cart",
    "/checkout",
    "/payment",
    "/pay",
    "/order",
    "/orders",
    "/invoice",
    "/billing",
    "/shipping",
    "/track",
    "/tracking",
    "/uploads",
    "/upload",
    "/files",
    "/file",
    "/documents",
    "/docs",
    "/downloads",
    "/download",
    "/gallery",
    "/images",
    "/img",
    "/media",
    "/music",
    "/videos",
    "/video",
    "/audio",
    "/static",
    "/assets",
    "/css",
    "/js",
    "/fonts",
    "/themes",
    "/templates",
    "/vendor",
    "/modules",
    "/components",
    "/includes",
    "/lib",
    "/libs",
    "/source",
    "/sources",
    "/robots.txt",
    "/sitemap.xml",
    "/ads.txt",
    "/humans.txt",
    "/security.txt",
    "/privacy-policy",
    "/terms",
    "/terms-of-service",
    "/tos",
    "/legal",
    "/license",
    "/cookies",
    "/index.php",
    "/index.html",
    "/home",
    "/about",
    "/about-us",
    "/contact",
    "/contact-us",
    "/support",
    "/help",
    "/faq",
    "/blog",
    "/news",
    "/rss",
    "/press",
    "/events",
    "/private",
    "/restricted",
    "/confidential",
    "/hidden",
    "/secret",
    "/vault",
    "/keys",
    "/key",
    "/security",
    "/security_check",
    "/admin_secret",
    "/beta",
    "/test",
    "/staging",
    "/demo",
    "/status",
    "/status.php",
    "/health",
    "/monitoring",
    "/ping",
    "/diagnostics",
    
    ];
    
    $found = [];

    foreach ($directories as $dir) {
        $url = "https://$domain$dir";
        $headers = @get_headers($url);
        if ($headers && strpos($headers[0], '200') !== false) {
            $found[] = "<strong>$dir</strong> | found";
        }
    }

    return !empty($found) ? implode("<br>", $found) : "Nothing found.";
}

function runNmapScan($domain) {
    // Шаг 1: Проверка наличия nmap
    $nmapPath = shell_exec('which nmap');
    if (empty(trim($nmapPath))) {
        return "<p>Ошибка: Nmap не установлен.</p>";
    }

    // Шаг 2: Сканирование портов с помощью nmap
    $command = "nmap -sV -A -Pn " . escapeshellarg($domain) . " 2>&1";
    $output = shell_exec($command);

    if (empty(trim($output))) {
        return "<p>Ошибка: Nmap не вернул результатов.</p>";
    }

    // Шаг 3: Извлечение глобального IP-адреса из строки "Nmap scan report for domain.com (127.0.0.1)"
    if (!preg_match('/Nmap scan report for [^\(]+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/', $output, $matches)) {
        return "<p>Ошибка: Не удалось найти IP-адрес в отчете nmap.</p>";
    }

    $ip = $matches[1]; // Глобальный IP-адрес

    // Вывод полного отчета nmap
    $nmapReport = "<h4 style='color:black;'>Отчет nmap:</h4><pre>" . htmlspecialchars($output) . "</pre>";

    // Шаг 4: Проверка анонимного доступа к сервисам
    $services = [
        "FTP" => "echo 'anonymous\r\rQUIT\r' | timeout 5 nc $ip 21", // Завершение командой QUIT
        "SMTP" => "timeout 5 nc $ip 25", // SMTP обычно не требует явного завершения
        "POP3" => "echo 'QUIT' | timeout 5 nc $ip 110", // Завершение командой QUIT
        "IMAP" => "echo 'LOGOUT' | timeout 5 nc $ip 143", // Завершение командой LOGOUT
        "Redis" => "timeout 5 redis-cli -h $ip PING",
        "MySQL" => "timeout 5 mysql -u root -h $ip -e 'SHOW DATABASES;'",
        "PostgreSQL" => "timeout 5 psql -h $ip -U postgres -c '\l'",
        "MongoDB" => "timeout 5 mongo $ip:27017 --eval 'db.stats()'",
        "Memcached" => "timeout 5 echo 'stats' | nc $ip 11211",
        "SMB" => "timeout 5 smbclient -L //$ip -N", // SMB завершается автоматически
        "Elasticsearch" => "timeout 5 curl -s http://$ip:9200/",
        "Rsync" => "timeout 5 rsync $ip::",
        "HTTP" => "timeout 5 curl -s http://$ip/",
        "HTTPS" => "timeout 5 curl -k -s https://$ip/",
        "NFS" => "timeout 5 showmount -e $ip",
        "LDAP" => "timeout 5 ldapsearch -x -h $ip -b '' -s base",
        "Docker API" => "timeout 5 curl -s http://$ip:2375/containers/json",
        "Kubernetes API" => "timeout 5 curl -s http://$ip:8001/api",
        "CouchDB" => "timeout 5 curl -s http://$ip:5984/_all_dbs"
    ];

    $successfulConnections = [];
    foreach ($services as $service => $cmd) {
        $output = shell_exec($cmd . " 2>&1");
        if (!empty(trim($output)) && !preg_match('/(failed|denied|error|refused|unable|timed out)/i', $output)) {
            if ($service === "FTP") {
                // Дополнительная команда LIST с завершением QUIT
                $listCmd = "echo 'anonymous\rLIST\rQUIT\r' | timeout 5 nc $ip 21";
                $listOutput = shell_exec($listCmd . " 2>&1");
                if (!empty(trim($listOutput)) && !preg_match('/(failed|denied|error|refused|unable|timed out)/i', $listOutput)) {
                    $successfulConnections[] = "<strong>$service</strong>: Successful connection<br><pre>$listOutput</pre>";
                }
            } elseif ($service === "SMB") {
                // Команда ls с автоматическим завершением
                $listCmd = "timeout 5 smbclient //$ip/share -N -c 'ls'";
                $listOutput = shell_exec($listCmd . " 2>&1");
                if (!empty(trim($listOutput)) && !preg_match('/(failed|denied|error|refused|unable|timed out)/i', $listOutput)) {
                    $successfulConnections[] = "<strong>$service</strong>: Successful connection<br><pre>$listOutput</pre>";
                }
            } else {
                $successfulConnections[] = "<strong>$service</strong>: Successful connection<br><pre>$output</pre>";
            }
        }
    }

    // Формирование финального вывода
    $results = "";
    if (!empty($successfulConnections)) {
        $results .= "<h3 style='color:black;'>Check for Anonymous Access to Services</h3><h4 style='color:black;'>IP: $ip</h4>" . implode("", $successfulConnections);
    } else {
        $results .= "<p>Nothing found.</p>";
    }

    return $nmapReport . $results;
}

// Функция WAF Detection
function detectWaf($domain) {
    $command = "wafw00f https://" . escapeshellarg($domain) . " 2>&1";
    $output = shell_exec($command);
    return !empty(trim($output)) ? "<pre>" . htmlspecialchars($output) . "</pre>" : "Nothing found.";
}

// Функция API Endpoint Finder
function findApiEndpoints($domain) {
    $endpoints = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/graphql/schema",
    "/graphql/playground",
    "/graphql/query",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/rest/v3",
    "/rest/auth",
    "/rest/users",
    "/rest/posts",
    "/rest/orders",
    "/rest/products",
    "/rest/settings",
    "/rest/system",
    "/wp-json",
    "/wp-json/wp/v1",
    "/wp-json/wp/v2",
    "/wp-json/wp/v3",
    "/wp-json/oembed",
    "/wp-json/jwt-auth/v1/token",
    "/wp-json/contact-form-7/v1",
    "/wp-json/wc/v3",
    "/wp-json/wc/v2",
    "/wp-json/acf/v3",
    "/wp-json/yoast/v1",
    "/wp-json/wpml/v1",
    "/wp-json/litespeed/v1",
    "/joomla/api",
    "/joomla/rest",
    "/joomla/v1",
    "/joomla/v2",
    "/joomla/users",
    "/joomla/articles",
    "/joomla/categories",
    "/joomla/contacts",
    "/joomla/tags",
    "/joomla/menu",
    "/joomla/modules",
    "/joomla/templates",
    "/joomla/plugins",
    "/opencart/api",
    "/opencart/rest",
    "/opencart/v1",
    "/opencart/v2",
    "/opencart/products",
    "/opencart/categories",
    "/opencart/customers",
    "/opencart/orders",
    "/opencart/coupons",
    "/opencart/payments",
    "/opencart/shipping",
    "/opencart/stats",
    "/prestashop/api",
    "/prestashop/rest",
    "/prestashop/v1",
    "/prestashop/v2",
    "/prestashop/products",
    "/prestashop/customers",
    "/prestashop/orders",
    "/prestashop/cart",
    "/prestashop/categories",
    "/prestashop/manufacturers",
    "/prestashop/stock",
    "/prestashop/addresses",
    "/prestashop/shipping",
    "/prestashop/returns",
    "/maltego/api",
    "/maltego/rest",
    "/maltego/v1",
    "/maltego/v2",
    "/maltego/transform",
    "/maltego/graph",
    "/maltego/entities",
    "/maltego/settings",
    "/auth",
    "/auth/token",
    "/auth/login",
    "/auth/logout",
    "/auth/refresh",
    "/auth/validate",
    "/oauth",
    "/oauth2",
    "/oauth/token",
    "/oauth/authorize",
    "/jwt",
    "/jwt/token",
    "/jwt/verify",
    "/users",
    "/users/v1",
    "/users/v2",
    "/users/me",
    "/users/profile",
    "/users/settings",
    "/users/roles",
    "/users/permissions",
    "/users/notifications",
    "/users/activity",
    "/admin",
    "/admin/api",
    "/admin/settings",
    "/admin/logs",
    "/admin/analytics",
    "/admin/monitoring",
    "/admin/system",
    "/admin/backup",
    "/admin/reports",
    "/orders",
    "/orders/v1",
    "/orders/v2",
    "/orders/status",
    "/orders/details",
    "/orders/history",
    "/orders/cancel",
    "/orders/refund",
    "/payments",
    "/payments/v1",
    "/payments/v2",
    "/payments/gateway",
    "/payments/stripe",
    "/payments/paypal",
    "/payments/bitcoin",
    "/payments/transactions",
    "/shop",
    "/shop/api",
    "/shop/products",
    "/shop/cart",
    "/shop/checkout",
    "/shop/orders",
    "/shop/customers",
    "/shop/coupons",
    "/shop/reviews",
    "/shop/stock",
    "/inventory",
    "/inventory/stock",
    "/inventory/products",
    "/inventory/reports",
    "/support",
    "/support/tickets",
    "/support/chat",
    "/support/faq",
    "/support/docs",
    "/support/feedback",
    "/blog",
    "/blog/api",
    "/blog/posts",
    "/blog/categories",
    "/blog/comments",
    "/blog/tags",
    "/blog/recent",
    "/notifications",
    "/notifications/list",
    "/notifications/unread",
    "/notifications/read",
    "/notifications/settings",
    "/settings",
    "/settings/general",
    "/settings/security",
    "/settings/privacy",
    "/settings/api-keys",
    "/settings/integrations",
    "/analytics",
    "/analytics/v1",
    "/analytics/v2",
    "/analytics/traffic",
    "/analytics/sales",
    "/analytics/events",
    "/analytics/reports",
    "/reports",
    "/reports/v1",
    "/reports/v2",
    "/reports/sales",
    "/reports/users",
    "/reports/security",
    "/integrations",
    "/integrations/list",
    "/integrations/connect",
    "/integrations/disconnect",
    "/integrations/status",
    "/integrations/settings",
    "/cms",
    "/cms/api",
    "/cms/pages",
    "/cms/blocks",
    "/cms/media",
    "/cms/settings",
    "/wordpress",
    "/wp-json/wp/v1/plugins",
    "/wp-json/wp/v1/themes",
    "/wp-json/wp/v1/users",
    "/wp-json/wp/v1/media",
    "/wp-json/wp/v1/settings",
    "/magento",
    "/magento/api",
    "/magento/rest",
    "/magento/v1",
    "/magento/v2",
    "/magento/products",
    "/magento/customers",
    "/magento/orders",
    "/magento/cart",
    "/magento/shipping",
    "/magento/stock",
    "/magento/pricing",
    "/magento/coupons",
    "/magento/returns",
    "/drupal",
    "/drupal/api",
    "/drupal/v1",
    "/drupal/v2",
    "/drupal/content",
    "/drupal/users",
    "/drupal/comments",
    "/drupal/taxonomy",
    "/drupal/views",
    "/drupal/files",
    "/drupal/config",
    "/drupal/cache",
    "/drupal/performance",
    "/drupal/modules",
    "/typo3",
    "/typo3/api",
    "/typo3/rest",
    "/typo3/v1",
    "/typo3/v2",
    "/typo3/pages",
    "/typo3/content",
    "/typo3/media",
    "/typo3/settings",
    "/typo3/extensions",
    "/typo3/cache",
    "/typo3/themes",
    "/typo3/seo",
    "/typo3/backup",
    "/typo3/roles",
    "/typo3/permissions",
    "/api/random",
    "/api/proxy",
    "/api/ip",
    "/api/geoip",
    "/api/timezone",
    "/api/qrcode",
    "/api/barcode",
    "/api/image",
    "/api/video",
    "/api/music",
    "/api/stream",
    "/api/gateway",
    "/api/messages",
    "/api/comments",
    "/api/likes",
    "/api/friends",
    "/api/followers",
    "/api/chat",
    "/api/captcha",
    "/api/cdn",
    "/api/sync",
    "/api/backup",
    "/api/recovery",
    "/api/security",
    "/api/antifraud",
    "/api/encryption",
    "/api/blocklist",
    "/api/allowlist",
    "/api/spam",
    "/api/logs",
    "/api/dns",
    "/api/network",
    "/api/firewall",
    "/v6/nonces",
    "/v4/domains/validation",
    "/v4/feature-configs",
    "/v4/links/ABC123",
    "/v3/bootstrap",
    "/v3/experiments",
    "/v3/health",
    "/v3/logging/mobile/logs",
    "/v3/status",
    "/v3/version",
    "/v3/sessions",
    "/v3/sessions/thirdparty",
    "/v6/users",
    "/v3/users/email",
    "/v3/users/forgot-password",
    "/v3/users/reset-password",
    "/v3/users/reset-password?request=true",
    "/v3/users/thirdparty",
    "/v3/users/thirdparty/exchange",
    "/v3/users/update-password",
    "/v4/sms/sessions",
    "/v4/sms/verifycode",
    "/v4/sms/users/update-password/sendcode",
    "/v4/sms/users/update-password",
    "/v4/sms/verification/500/sendcode",
    "/v5/favorites",
    "/v4/hashtags/valid",
    "/v4/hashtags/recommend",
    "/v4/me/blocks?page=1",
    "/v4/me/muted-profiles",
    "/v4/me/profile/",
    "/v4/profiles/{{myProfileId}}",
    "/v4/profiles/reachable",
    "/v4/profiles/status",
    "/v4/profiles/supportedFeatures/{{myProfileId}}",
    "/v4/profile-tags/categories",
    "/v3.1/blockby",
    "/v3.1/blockby/1001210",
    "/v3.1/me/blocks",
    "/v3.1/me/profile",
    "/v3/me/blocks/1001210",
    "/v3/me/favorites/3",
    "/v3/me/legal-agreements",
    "/v3/me/profile",
    "/v3/me/prefs",
    "/v3/me/prefs/phrases",
    "/v3/me/prefs/phrases/bfc44381-c215-35f7-874a-ae512360836a",
    "/v3/me/prefs/settings",
    "/v3/me/subscriptions",
    "/v3/me/subscriptions?platform=android",
    "/v3/me/subscriptions?status=nonexpired",
    "/v3/profiles",
    "/v5/me/vendor-token",
    "/v5/rewarded-chats",
    "/v4/audio-call",
    "/v4/audio-call/join",
    "/v4/audio-call/renew",
    "/v4/audio-call/leave",
    "/v4/pics/expiring/status",
    "/v4/pics/expiring",
    "/v4/phrases/frequency/phraseId=63db06c8-9915-3279-b07c-1fd925013acc",
    "/v4/recognition/face",
    "/v4/recognition/chat",
    "/v4/views",
    "/v4/views/54986486",
    "/v3.1/chat/backup",
    "/v3.1/flags/112788",
    "/v3.1/groupchat/canbeinvited",
    "/v3.1/groupchat/caninvite/44906526",
    "/v3.1/groupchat/invitation-link-code/22345",
    "/v3.1/me/push-conversations/908f72c2d4aea3998a3400c9ad539768",
    "/v3/ad-colony/transactions?amount=4&uid=2&zone=3&id=1&verifier=10&udid=7&odin1=8&open_udid=6&mac_sha1=9&custom_id=49645¤cy=5",
    "/v3/mopub/transactions?ad_revenue=4.0&ad_unit_id=2&advertising_id=3&id=1¤cy_type=10¤cy_value=7&customer_id=8&id=6&placement_id=9×tamp=49645&verifier=5",
    "/v3/video-call",
    "/v3/video-call/12345",
    "/v4/consumables",
    "/v4/consumables/BOOST",
    "/v4/consumables/boost/report",
    "/v4/store/products",
    "/v4/store/products/consumables",
    "/v4/store/products/com.grindr.productId",
    "/v4/store/status",
    "/v3.1/store/grindrstore/coupons",
    "/v3.1/store/itunes/purchases",
    "/v3.1/store/itunes/purchases/restorations",
    "/v3.1/store/googleplay/purchases",
    "/v3.1/store/googleplay/purchases/restorations",
    "/v3.1/store/itunes/events",
    "/v3.1/store/products/com.grindr.product",
    "/v3/stripe/events",
    "/api-docs",
    "/swagger",
    "/swagger/index.html",
    "/api/rest/api-docs",
    "/api/rest/swagger.json",
    "/products",
    "/api/products",
    "/openapi/",
    "/openapi/v1/",
    "/openapi/v2/",
    "/openapi/v3/",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/swagger.json",
    "/documentation",
    "/documentation/swagger",
    "/documentation/openapi",
    "/swagger/docs/v1",
    "/swagger/docs/v2",
    "/swagger/docs/v3",
    "/swagger-ui.html#/",
    "/swagger-ui/index.html#/",
    "/openapi/ui",
    "/swagger-ui/v1/",
    "/swagger-ui/v2/",
    "/swagger-ui/v3/",
    "/api/swagger-ui.html",
    "/api/swagger-ui/",
    "/api/documentation",
    "/v1/documentation",
    "/v2/documentation",
    "/v3/documentation",
    "/swagger-resources"
];
    $found = [];

    foreach ($endpoints as $ep) {
        $url = "https://$domain$ep";
        $headers = @get_headers($url);
        if ($headers && strpos($headers[0], '200') !== false) {
            $found[] = "<strong>$ep</strong> | found";
        }
    }

    return !empty($found) ? implode("<br>", $found) : "Nothing found.";
}


// Функция для поиска backup-файлов
function checkBackupFiles($domain) {
    // Список распространённых backup-файлов и директорий
$backupFiles = [
    "/backup",
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.bak",
    "/backup.db",
    "/db_backup",
    "/db_backup.sql",
    "/db_backup.zip",
    "/db_backup.tar.gz",
    "/db_backup.bak",
    "/db_backup.db",
    "/site_backup",
    "/site_backup.zip",
    "/site_backup.tar.gz",
    "/site_backup.sql",
    "/old",
    "/old_site",
    "/archive",
    "/archives",
    "/backups",
    "/bak",
    "/bak.sql",
    "/bak.zip",
    "/bak.tar.gz",
    "/dump.sql",
    "/dump.zip",
    "/dump.tar.gz",
    "/config.bak",
    "/config.old",
    "/config_backup",
    "/config_backup.php",
    "/config_backup.json",
    "/wp-config.bak",
    "/wp-config.old",
    "/wp-content/backup",
    "/wp-content/backups",
    "/wp-content/uploads/backup",
    "/wp-content/uploads/backups",
    "/wp-content/uploads/site_backup",
    "/wp-content/uploads/db_backup",
    "/admin/backup",
    "/admin/backups",
    "/admin/db_backup",
    "/admin/config_backup",
    "/logs/backup",
    "/logs/backups",
    "/logs/db_backup",
    "/logs/config_backup",
    "/uploads/backup",
    "/uploads/backups",
    "/uploads/db_backup",
    "/files/backup",
    "/files/backups",
    "/data/backup",
    "/data/backups",
    "/data/db_backup",
    "/data/config_backup",
    "/database/backup",
    "/database/backups",
    "/database/db_backup",
    "/database/config_backup",
    "/sql/backup",
    "/sql/backups",
    "/sql/db_backup",
    "/sql/config_backup",
    "/tmp/backup",
    "/tmp/backups",
    "/tmp/db_backup",
    "/tmp/config_backup",
    "/var/backup",
    "/var/backups",
    "/var/db_backup",
    "/var/config_backup",
    "/storage/backup",
    "/storage/backups",
    "/storage/db_backup",
    "/storage/config_backup",
    "/cache/backup",
    "/cache/backups",
    "/cache/db_backup",
    "/cache/config_backup",
    "/public_html/backup",
    "/public_html/backups",
    "/public_html/db_backup",
    "/public_html/config_backup",
    "/htdocs/backup",
    "/htdocs/backups",
    "/htdocs/db_backup",
    "/htdocs/config_backup",
    "/www/backup",
    "/www/backups",
    "/www/db_backup",
    "/www/config_backup",
    "/web/backup",
    "/web/backups",
    "/web/db_backup",
    "/web/config_backup",
    "/home/backup",
    "/home/backups",
    "/home/db_backup",
    "/home/config_backup",
    "/root/backup",
    "/root/backups",
    "/root/db_backup",
    "/root/config_backup",
    "/backup.zip",
    "/backup.tar",
    "/backup.tar.gz",
    "/backup.rar",
    "/backup.sql",
    "/backup.db",
    "/backup_old.zip",
    "/backup_2024.zip",
    "/backup_2023.zip",
    "/backup_latest.zip",
    "/backup-final.zip",
    "/backup-final.sql",
    "/backup-prod.zip",
    "/backup-dev.zip",
    "/backup-db.sql",
    "/backup-site.tar.gz",
    "/backup-wordpress.zip",
    "/backup-wp.tar.gz",
    "/site-backup.zip",
    "/site-backup.tar",
    "/site-backup.sql",
    "/full-backup.zip",
    "/full_backup.tar.gz",
    "/full-backup-2024.zip",
    "/fullbackup.sql",
    "/old-backup.zip",
    "/old_backup.sql",
    "/daily-backup.zip",
    "/weekly-backup.zip",
    "/monthly-backup.zip",
    "/admin-backup.zip",
    "/admin.bak",
    "/root-backup.zip",
    "/server-backup.sql",
    "/server_backup.tar",
    "/database-backup.zip",
    "/db_backup.sql",
    "/dump.sql",
    "/dump.tar.gz",
    "/mysql-backup.sql",
    "/mysql-dump.sql",
    "/postgres-backup.sql",
    "/db-dump.sql",
    "/db_dump_2023.sql",
    "/db_dump_latest.sql",
    "/config_backup.tar.gz",
    "/config.old",
    "/config_backup.zip",
    "/www-backup.zip",
    "/www.tar.gz",
    "/www.bak",
    "/web-backup.tar.gz",
    "/web_backup_2023.zip",
    "/dev-backup.zip",
    "/prod-backup.zip",
    "/staging-backup.zip",
    "/test-backup.sql",
    "/website.bak",
    "/wordpress-backup.zip",
    "/wp_backup.sql",
    "/wp-config.bak",
    "/wp-config.php~",
    "/wp-content.tar.gz",
    "/uploads-backup.zip",
    "/uploads.tar",
    "/uploads.bak",
    "/home_backup.tar.gz",
    "/var_backup.tar.gz",
    "/etc_backup.tar.gz",
    "/nginx.conf.bak",
    "/apache.conf.bak",
    "/logs_backup.tar.gz",
    "/access_logs.tar",
    "/error_logs.bak",
    "/logs-old.zip",
    "/cpanel-backup.tar.gz",
    "/cpanel_fullbackup.tar.gz",
    "/plesk-backup.zip",
    "/webmin-backup.tar",
    "/site_2024-07-01.tar.gz",
    "/public_html_backup.tar.gz",
    "/public_html_old.tar",
    "/public_html_2024.sql",
    "/phpinfo.bak",
    "/config.inc.old",
    "/credentials.bak",
    "/password_backup.txt",
    "/secrets.txt",
    "/credentials.tar.gz",
    "/db_credentials.sql",
    "/old_db.sql",
    "/sql_old.sql",
    "/website_OLD.zip",
    "/website_2023.bak",
    "/backup_07-2024.zip",
    "/snapshot.zip",
    "/snapshot-2024-07.tar.gz",
    "/snapshot-db.sql",
    "/export.sql",
    "/export_2023.sql",
    "/export_db.zip",
    "/export_backup.tar.gz",
    "/export_old.sql",
    "/db_export.zip",
    "/db_export.sql",
    "/wp-export.xml",
    "/wp-db-export.sql",
    "/magento_backup.sql",
    "/magento.tar.gz",
    "/drupal_backup.tar.gz",
    "/drupal_old.sql",
    "/joomla_backup.tar",
    "/laravel_backup.zip",
    "/laravel.env.bak",
    "/node_backup.tar",
    "/node_modules_backup.zip",
    "/react_backup.zip",
    "/vue_backup.tar",
    "/angular_backup.tar.gz",
    "/site_clone.zip",
    "/clone.tar.gz",
    "/duplicator-backup.zip",
    "/snapshot-db.tar.gz",
    "/zzz-backup.tar.gz",
    "/@backup.tar.gz",
    "/test_db.bak",
    "/test_dump.sql",
    "/temp_backup.zip",
    "/tmp_backup.tar",
    "/cache_backup.zip",
    "/archive.tar.gz",
    "/archive_2023.zip",
    "/system_backup.tar.gz",
    "/shop_backup.sql",
    "/store_backup.tar",
    "/ecommerce_backup.zip",
    "/opencart_backup.sql",
    "/prestashop_backup.tar.gz",
    "/commerce_backup.sql",
    "/admin.sql",
    "/admin_panel.tar",
    "/panel_backup.zip",
    "/portal_backup.tar.gz",
    "/api_backup.sql",
    "/api_old_backup.tar.gz",
    "/api_dev_backup.tar",
    "/api_prod_backup.tar",
    "/backend_backup.sql",
    "/frontend_backup.zip",
    "/site_package.zip",
    "/complete_backup.zip",
    "/mirror_backup.tar",
    "/staging_site.tar.gz",
    "/staging_db.sql",
    "/production_site.tar.gz",
    "/dev_site_backup.tar",
    "/prod_db.sql",
    "/server_config_backup.zip",
    "/server_files_backup.tar",
    "/nginx_backup.conf",
    "/apache_backup.conf",
    "/ftp_backup.zip",
    "/ssh_config_backup",
    "/.env.bak",
    "/.htaccess.bak",
    "/config.json.bak",
    "/settings_old.py",
    "/settings.py.bak",
    "/env_backup.zip",
    "/config_backup_2024.tar.gz",
    "/login_data.bak",
    "/tokens.txt",
    "/keys.tar.gz",
    "/ssl_backup.zip",
    "/cert_backup.tar.gz",
    "/private.key.bak",
    "/ssh_keys_backup.zip",
    "/vpn_config.bak",
    "/mail_backup.tar.gz",
    "/smtp_settings.bak",
    "/mail_config.tar",
    "/logs_2024.tar.gz",
    "/sessions_backup.zip",
    "/app_backup.tar",
    "/app_data_backup.sql",
    "/static_backup.tar",
    "/media_backup.zip",
    "/assets_backup.tar.gz",
    "/uploads_2023.tar",
    "/uploads_2024.tar",
    "/old_uploads.bak",
    "/site_assets.tar",
    "/themes_backup.zip",
    "/plugins_backup.tar",
    "/wordpress_plugins_backup.zip",
    "/joomla_plugins_backup.tar",
    "/drupal_modules_backup.tar",
    "/themes_old.zip",
    "/old_plugins.tar.gz",
    "/images_backup.zip",
    "/pictures_backup.tar",
    "/gallery_backup.tar.gz",
    "/photo_archive.zip",
    "/video_backup.tar.gz",
    "/music_backup.zip",
    "/media_old.tar",
    "/fonts_backup.zip",
    "/css_backup.tar",
    "/js_backup.tar",
    "/static_old.tar.gz",
    "/favicon_backup.ico",
    "/index_old.html",
    "/old_site.tar.gz",
    "/restore-point.tar",
    "/system_restore.tar.gz",
    "/recovery.zip",
    "/backup_copy.sql",
    "/backup_version2.tar",
    "/final_dump.sql",
    "/test_copy.tar.gz",
    "/logs_critical.tar",
    "/crash_report.tar.gz",
    "/bugreport_backup.tar",
    "/user_data_backup.zip",
    "/session_data.sql",
    "/cookie_backup.txt",
    "/analytics_backup.tar",
    "/stats_backup.tar.gz",
    "/metrics_backup.zip",
    "/firewall_backup.conf",
    "/waf_backup.tar",
    "/waf_logs.tar",
    "/security_backup.zip",
    "/vulnerability_scan.tar",
    "/antivirus_logs.tar",
    "/scan_results_backup.zip",
    "/pen_test_report.tar.gz",
    "/pentest_backup.sql",
    "/hacker_logs.tar",
    "/hack_attempts_backup.zip",
    "/cyber_security_backup.tar",
    "/malware_scan_backup.tar",
    "/rdp_backup.zip",
    "/ssh_backup_config",
    "/vps_backup.tar",
    "/cloud_backup_2023.tar.gz",
    "/aws_backup.tar",
    "/gcp_backup.tar",
    "/azure_backup.tar.gz",
    "/docker_backup.tar",
    "/kubernetes_backup.yaml",
    "/swarm_backup.tar",
    "/microservice_backup.tar",
    "/flask_backup.tar",
    "/django_backup.zip",
    "/express_backup.tar",
    "/backup_config.yaml",
    "/user_accounts.bak",
    "/employee_data.tar.gz",
    "/hr_backup.zip",
    "/finance_backup.tar",
    "/invoice_data_backup.zip",
    "/accounting_backup.tar.gz",
    "/tax_backup_2023.tar",
    "/transactions_backup.sql",
    "/payment_logs.tar",
    "/stripe_backup.tar.gz",
    "/paypal_backup.tar",
    "/logs_2024-07-01.tar",
    "/1_backup.zip",
    "/2_backup.zip",
    "/3_backup.sql",
    "/last_backup.zip",
    "/this_backup.tar.gz",
    "/safe_backup.tar",
    "/ghost_backup.tar.gz",
    "/hidden_backup.zip",
    "/secret_backup.tar",
    "/legacy_backup.sql",
    "/project1_backup.tar",
    "/project2_backup.zip",
    "/projectA_backup.sql",
    "/archive-old.tar.gz",
    "/upload.bak",
    "/config.php.bak",
    "/database.php.bak",
    "/connection.bak",
    "/credentials.env.bak",
    "/users.bak",
    "/members.sql",
    "/login.bak",
    "/register.bak",
    "/install.old",
    "/install.tar",
    "/init_backup.zip",
    "/legacy.tar.gz",
    "/v1_backup.zip",
    "/v2_backup.zip",
    "/api_backup_2024.tar",
    "/snapshot_07-12-2024.tar.gz",
    "/config.ini",
    "/config_backup.ini",
    "/config_old.ini",
    "/config~.ini",
    "/backup_config.ini",
    "/database.ini",
    "/database_backup.ini",
    "/db_config.ini",
    "/db_settings.ini",
    "/wp-config.ini",
    "/wp_settings.ini",
    "/mail.ini",
    "/mail_config.ini",
    "/smtp.ini",
    "/smtp_config.ini",
    "/php.ini",
    "/php_old.ini",
    "/php_backup.ini",
    "/nginx.ini",
    "/apache.ini",
    "/httpd.ini",
    "/server.ini",
    "/system.ini",
    "/env.ini",
    "/environment.ini",
    "/app.ini",
    "/app_config.ini",
    "/settings.ini",
    "/settings_backup.ini",
    "/user.ini",
    "/user_config.ini",
    "/admin.ini",
    "/auth.ini",
    "/login.ini",
    "/email.ini",
    "/site.ini",
    "/local.ini",
    "/local_config.ini",
    "/debug.ini",
    "/debug_config.ini",
    "/test.ini",
    "/prod.ini",
    "/dev.ini",
    "/staging.ini",
    "/version.ini",
    "/theme.ini",
    "/plugins.ini",
    "/modules.ini",
    "/firewall.ini",
    "/waf.ini"
];

    $found = [];

    foreach ($backupFiles as $file) {
        $url = "https://$domain$file";
        $headers = @get_headers($url);
        if ($headers && strpos($headers[0], '200') !== false) {
            $found[] = "<strong>$file</strong> | found";
        }
    }

    return !empty($found) ? implode("<br>", $found) : "Nothing found.";
}



// Функция WHOIS
function getWhoisInfo($domain) {
    $output = shell_exec("whois " . escapeshellarg($domain));
    return !empty(trim($output)) ? "<pre>" . htmlspecialchars($output) . "</pre>" : "Информация не найдена.";
}

// Функция SSL Certificate
function getSSLCert($domain) {
    $parsed_url = parse_url("https://$domain");
    $host = $parsed_url['host'];

    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
    $fp = @stream_socket_client("ssl://$host:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

    if (!$fp) {
        return "Ошибка: Не удалось подключиться к серверу.";
    }

    $cert = stream_context_get_params($fp)['options']['ssl']['peer_certificate'];
    fclose($fp);
    $cert_data = openssl_x509_parse($cert);

    return "<pre>" . htmlspecialchars(print_r($cert_data, true)) . "</pre>";
}

function checkSecurityHeaders($domain) {
    // Проверяем доступность домена через DNS
    if (!isDomainAccessible($domain)) {
        return "<p>Ошибка: Домен $domain недоступен или не существует.</p>";
    }

    // Формируем URL (по умолчанию HTTPS)
    $url = strpos($domain, 'http') === false ? "https://$domain" : $domain;

    // Получаем заголовки с таймаутом и User-Agent
    $headers = getHeadersWithUserAgent($url);
    if (!$headers || !is_array($headers) || !isset($headers[0]) || strpos($headers[0], '200') === false) {
        // Если HTTPS не работает, пробуем HTTP
        $url = "http://$domain";
        $headers = getHeadersWithUserAgent($url);
    }

    // Если заголовки всё ещё не получены, возвращаем ошибку
    if (!$headers || !is_array($headers) || !isset($headers[0]) || strpos($headers[0], '200') === false) {
        return "<p>Ошибка: Не удалось получить заголовки для домена $domain.</p>";
    }

    // Преобразуем заголовки в ассоциативный массив
    $headersAssoc = [];
    foreach ($headers as $key => $value) {
        if (is_string($key)) {
            $headersAssoc[$key] = $value;
        }
    }

    // Список обязательных флагов безопасности
    $requiredHeaders = [
        'Strict-Transport-Security' => 'HSTS Not Enabled – HTTPS Traffic Vulnerable to Sniffing.',
        'Content-Security-Policy' => 'Lack of Protection Against XSS and Script Injection.',
        'X-Content-Type-Options' => 'MIME-sniffing Possible (Missing "nosniff" Header).',
        'X-Frame-Options' => 'Clickjacking Possible (Page Can Be Embedded in an iframe).',
        'X-XSS-Protection' => 'XSS Protection Not Configured or Disabled.',
        'Referrer-Policy' => 'Referrer Policy Not Configured (Sensitive Information May Leak).',
        'Permissions-Policy' => 'Browser Feature Control (Geolocation, Camera, etc.) Not Configured.',
        'Cross-Origin-Embedder-Policy' => 'No Protection Against Insecure Resource Loading in iframe.',
        'Cross-Origin-Opener-Policy' => 'Window Context Isolation Not Enabled (May Be Vulnerable to Side-Channel Attacks).',
        'Cross-Origin-Resource-Policy' => 'No Restriction on Cross-Origin Resource Access.',
        'Expect-CT' => 'Certificate Transparency Policy Not Set (Fake SSL Certificates May Be Accepted).',
        'Cache-Control' => 'Caching Rules Not Set (Private Information May Leak).',
        'Pragma' => 'No Protection Against Caching in Legacy Browsers.',
        'Expires' => 'Content Expiration Not Set (May Be Cached Longer Than Intended).',
        'Access-Control-Allow-Origin' => 'CORS Not Securely Configured (Susceptible to Attacks via Spoofed Origin).',
        'Server' => 'The "Server" Header Reveals Server Type and Version (Useful to an Attacker).',
        'X-Powered-By' => 'The "X-Powered-By" Header Reveals Backend Technology (e.g., PHP, Express, etc.).',
        'Set-Cookie' => 'Missing Cookie Security Flags: Secure, HttpOnly, SameSite.',
    ];

    // Формируем результаты проверки
    $results = [];
    foreach ($requiredHeaders as $header => $warning) {
        $results[] = isset($headersAssoc[$header])
            ? "<strong>$header:</strong> Найден ✅"
            : "<strong>$header:</strong> Отсутствует ❌ ($warning)";
    }

    // Возвращаем результаты
    return "<h3 style='color:black;'>Security Flags Check:</h3>" . implode("<br>", $results);
}

// Вспомогательные функции

function isDomainAccessible($domain) {
    $host = parse_url("https://$domain", PHP_URL_HOST);
    return checkdnsrr($host, 'A') || checkdnsrr($host, 'AAAA');
}

function getHeadersWithUserAgent($url) {
    $context = stream_context_create([
        'http' => [
            'method' => 'HEAD',
            'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n",
            'timeout' => 5,
        ],
    ]);
    return @get_headers($url, 1, $context);
}

// Функция для проверки TLS-шифров с помощью nmap
function checkTlsCiphers($domain) {
    // Добавляем протокол, если его нет
    $target = strpos($domain, 'http') === false ? "https://$domain" : $domain;

    // Извлекаем хост из URL
    $parsed_url = parse_url($target);
    $host = $parsed_url['host'] ?? '';

    if (empty($host)) {
        return "<p>Ошибка: Не удалось определить хост для домена $domain.</p>";
    }

    // Проверяем наличие nmap
    $nmapPath = shell_exec('which nmap');
    if (empty(trim($nmapPath))) {
        return "<p>Ошибка: Nmap не установлен.</p>";
    }

    // Выполняем команду nmap для проверки TLS-шифров
    $command = "nmap --script ssl-enum-ciphers -p 443 " . escapeshellarg($host) . " 2>&1";
    $output = shell_exec($command);

    if (empty(trim($output))) {
        return "<p>Ошибка: Nmap не вернул результатов для домена $domain.</p>";
    }

    // Возвращаем результат
    return "<h3 style='color:black;'></h3><pre>" . htmlspecialchars($output) . "</pre>";
}


function checkSubdomainTakeover($domain) {
$subdomains = [
    "ftp", "ssh", "mail", "www", "api", "dev", "test", "blog", "cms", "cdn",
    "db", "admin", "backup", "beta", "demo", "docs", "download", "forum", "help",
    "intranet", "jobs", "lab", "live", "login", "m", "mobile", "monitor", "news",
    "sip", "client", "support", "status", "iot", "device", "devices", "sensor", 
    "sensors", "control", "controller", "admin1", "login-panel", "staff-login",
    "a", "acceptatie", "access", "accounting", "accounts", "ad", "adm", "admin",
    "administrator", "ads", "adserver", "affiliate", "affiliates", "agenda", "alpha",
    "alumni", "analytics", "ann", "apollo", "app", "apps", "ar", "archive", "art",
    "assets", "atlas", "auth", "auto", "autoconfig", "autodiscover", "av", "ayuda",
    "b", "b2b", "backups", "banner", "barracuda", "bb", "bbs", "biblioteca", "billing",
    "blackboard", "blogs", "board", "book", "booking", "bookings", "broadcast-ip", "bsd",
    "bt", "bug", "bugs", "business", "c", "ca", "cache", "cacti", "cal", "calendar",
    "cam", "careers", "cart", "cas", "catalog", "catalogo", "catalogue", "cc", "cctv",
    "cdn1", "cdn2", "chat", "chimera", "chronos", "ci", "cisco", "citrix", "classroom",
    "clientes", "clients", "cloud", "cloudflare-resolve-to", "club", "cn", "co", "community",
    "conference", "config", "connect", "contact", "contacts", "content", "corp", "corporate",
    "correo", "correoweb", "cp", "cpanel", "crm", "cs", "css", "customers", "cvs", "d",
    "da", "data", "database", "db1", "db2", "dbadmin", "dbs", "dc", "de", "default",
    "demo2", "demon", "demostration", "descargas", "design", "desktop", "dev01", "dev1",
    "dev2", "development", "dialin", "diana", "direct", "directory", "dl", "dmz", "dns",
    "dns1", "dns2", "dns3", "dns4", "doc", "domain", "domain-controller", "domainadmin",
    "domaincontrol", "domaincontroller", "domaincontrolpanel", "domainmanagement", "domains",
    "downloads", "drupal", "e", "eaccess", "echo", "ecommerce", "edu", "ektron", "elearning",
    "email", "en", "eng", "english", "enterpriseenrollment", "enterpriseregistration", "erp",
    "es", "event", "events", "ex", "example", "examples", "exchange", "external", "extranet",
    "f", "facebook", "faq", "fax", "fb", "feedback", "feeds", "file", "files", "fileserver",
    "finance", "firewall", "folders", "forms", "foro", "foros", "forums", "foto", "fr",
    "free", "freebsd", "fs", "ftp1", "ftp2", "ftpadmin", "ftpd", "fw", "g", "galeria",
    "gallery", "game", "games", "gate", "gateway", "gilford", "gis", "git", "gmail",
    "go", "google", "groups", "groupwise", "gu", "guest", "guia", "guide", "gw", "health",
    "helpdesk", "hera", "heracles", "hercules", "hermes", "home", "homer", "host", "host2",
    "hosting", "hotspot", "hr", "hypernova", "i", "id", "idp", "im", "image", "images",
    "images1", "images2", "images3", "images4", "images5", "images6", "images7", "images8",
    "imail", "imap", "imap3", "imap3d", "imapd", "imaps", "img", "img1", "img2", "img3",
    "imgs", "imogen", "in", "incoming", "info", "inmuebles", "internal", "interno", "intra",
    "io", "ip", "ip6", "ipfixe", "iphone", "ipmi", "ipsec", "ipv4", "ipv6", "irc", "ircd",
    "is", "isa", "it", "ja", "jabber", "jboss", "jboss2", "jira", "job", "jobs", "jp",
    "js", "jupiter", "k", "kb", "kerberos", "l", "la", "laboratories", "laboratorio", "laboratory",
    "labs", "ldap", "legacy", "lib", "library", "link", "links", "linux", "lisa", "list",
    "lists", "live", "lms", "local", "localhost", "log", "loghost", "logon", "logs", "loopback",
    "love", "lp", "lync", "lyncdiscover", "m1", "m2", "magento", "mail01", "mail1", "mail2",
    "mail3", "mail4", "mail5", "mailadmin", "mailbackup", "mailbox", "mailer", "mailgate", "mailhost",
    "mailing", "mailman", "mailserver", "main", "manage", "manager", "mantis", "map", "maps",
    "market", "marketing", "mars", "master", "math", "mb", "mc", "mdm", "media", "meet",
    "member", "members", "mercury", "meta", "meta01", "meta02", "meta03", "meta1", "meta2",
    "meta3", "miembros", "mijn", "minerva", "mirror", "ml", "mm", "mob", "mobil", "monitor",
    "monitoring", "moodle", "movil", "mrtg", "ms", "msoid", "mssql", "munin", "music", "mx",
    "mx-a", "mx-b", "mx0", "mx01", "mx02", "mx03", "mx1", "mx2", "mx3", "my", "mysql",
    "mysql2", "n", "nagios", "nas", "nat", "nelson", "neon", "net", "netmail", "netscaler",
    "network", "network-ip", "networks", "new", "newmail", "newsgroups", "newsite", "newsletter", "nl",
    "noc", "novell", "ns0", "ns01", "ns02", "ns03", "ns10", "ns11", "ns12", "nt", "ntp",
    "ntp1", "oa", "office", "office2", "old", "oldmail", "oldsite", "oldwww", "on", "online",
    "op", "openbsd", "operation", "operations", "ops", "ora", "oracle", "origin", "orion", "os",
    "osx", "ou", "outgoing", "outlook", "owa", "ox", "painel", "panel", "partner", "partners",
    "pay", "payment", "payments", "pbx", "pcanywhere", "pda", "pegasus", "pendrell", "personal", "pgsql",
    "phoenix", "photo", "photos", "php", "phpmyadmin", "pm", "pma", "poczta", "pop", "pop3",
    "portal", "portfolio", "post", "postgres", "postgresql", "postman", "postmaster", "pp", "ppp", "pr",
    "pre-prod", "pre-production", "preprod", "press", "preview", "private", "pro", "prod", "production", "project",
    "projects", "promo", "proxy", "prueba", "pruebas", "pt", "pub", "public", "qa", "r", "ra",
    "radio", "radius", "ras", "rdp", "redirect", "redmine", "register", "relay", "remote", "remote2",
    "repo", "report", "reports", "repos", "research", "resources", "restricted", "reviews", "robinhood", "root",
    "router", "rss", "rt", "rtmp", "ru", "s1", "s2", "s3", "s4", "sa", "sales", "sample",
    "samples", "sandbox", "sc", "search", "secure", "security", "seo", "server", "server1", "server2",
    "service", "services", "sftp", "share", "sharepoint", "shell", "shop", "shopping", "signup", "sip",
    "site", "siteadmin", "sitebuilder", "sites", "skype", "sms", "smtp", "smtp1", "smtp2", "smtp3",
    "snmp", "social", "software", "solaris", "soporte", "sp", "spam", "speedtest", "sport", "sports",
    "sql", "sqlserver", "squirrel", "squirrelmail", "ssh", "ssl", "sslvpn", "sso", "st", "staff",
    "stage", "staging", "start", "stat", "static", "static1", "static2", "stats", "status", "storage",
    "store", "stream", "streaming", "student", "sun", "support", "survey", "sv", "svn", "t", "team",
    "tech", "telewerk", "telework", "temp", "test", "test1", "test2", "test3", "testing", "testsite",
    "testweb", "tfs", "tftp", "thumbs", "ticket", "tickets", "time", "tools", "trac", "track", "tracker",
    "tracking", "train", "training", "travel", "ts", "tunnel", "tutorials", "tv", "tw", "uat", "uk",
    "unix", "up", "update", "upload", "uploads", "us", "user", "users", "v2", "vc", "ventas", "video",
    "videos", "vip", "virtual", "vista", "vle", "vm", "vms", "vmware", "vnc", "vod", "voip", "vpn",
    "vpn1", "vpn2", "vpn3", "vps", "vps1", "vps2", "w3", "wap", "wc", "web", "web0", "web01", "web02",
    "web03", "web1", "web2", "web3", "web4", "web5", "webadmin", "webcam", "webconf", "webct", "webdb", "webdisk",
    "weblog", "webmail", "webmail2", "webmaster", "webmin", "webservices", "webstats", "webstore", "whm", "wifi", "wiki",
    "win", "win32", "windows", "wordpress", "work", "wp", "ws", "wsus", "ww", "ww0", "ww01", "ww02",
    "ww03", "ww1", "ww2", "ww3", "www-test", "www0", "www01", "www02", "www03", "www1", "www2", "www3",
    "www4", "www5", "www6", "www7", "www-live-direct", "www-live-redirect", "wwwm", "wwwold", "wwww", "xml", "zabbix",
    "zeus", "zimbra", "cp", "exchange", "mailserver", "mcp", "pop", "pop3", "ssh", "remote", "control", "controlpanel",
    "imap", "email", "calendar", "docs", "lists", "domain", "mysql", "ns", "managedomain", "manage", "mailcontrol", "post",
    "mail2", "hosting", "vps", "mx", "sites", "stats", "autoreply", "list", "domains", "apps", "gmail", "vpn",
    "start", "sip", "matrixstats", "dcp", "chat", "secure", "dns", "lyncdiscover", "dev01", "bj01", "mx1", "relay",
    "beta", "mailhost", "panel", "mssql", "mx2", "ww1", "ts", "svn", "mysql4ext", "smartstats", "mysql5ext", "mssqlint",
    "mysql4int", "mysql5int", "dns1", "files", "site", "mail3", "gallery", "store", "mobilemail", "static", "helpdesk", "ns6",
    "ils", "dm", "app", "gateway", "stage", "access", "preview", "outgoing", "incoming", "domaincontrolpanel", "wap", "sharepoint",
    "host", "ssl", "db", "clients", "smtp2", "domaincontrol", "dns2", "server1", "sql", "members", "extranet", "citrix", "cloud",
    "popd", "helm", "outlook", "manage-ds", "ms1", "photos", "irc", "sftp", "help", "sparkhost", "hcp", "ww", "e", "oldwww",
    "cal", "moodle", "forums", "projects", "ftp2", "testing", "pda", "live", "cctv", "git", "wwww", "smtpout", "dev2", "upload",
    "oldmail", "router", "search", "ww2", "mailer", "services", "edit", "newsletter", "ntp", "development", "dns0", "webmail2", "staff",
    "mydomain", "test2", "downloads", "dashboard", "manager", "info", "download", "smarterstats", "proxy", "uat", "server2", "domcontrol",
    "reports", "monitor", "facebook", "newsite", "customer", "gw", "img", "status", "temp", "legacy", "vle", "linux", "survey", "data",
    "ns5", "cpx", "remote2", "sandbox", "mail4", "london", "nagios", "ftp1", "jobs", "auto-mx", "connect", "music", "wordpress", "a-213-171-216-114",
    "manageyourdomain", "local", "wedding", "sms", "ww3", "correio", "online", "mercury", "pbx", "mx3", "wbsnhes", "vpn2", "sbs", "awstats",
    "dev1", "signup", "ww7", "orion", "phpmyadmin", "mail10", "mysqladmin", "rdp", "oldsite", "domainpanel", "server5", "rds", "meet", "exceptionto",
    "testweb", "mx0", "and", "andromeda", "domainmanager", "google", "proton", "md", "domainmanager", "iphone", "magento", "dolphin10", "stream",
    "library", "managevps", "internal", "billing", "config", "perseus", "smtpmail", "desktop", "shell", "marketing", "sales", "aquila", "boson",
    "proton-multi", "lyra", "hq", "orion2", "rt", "perseus2", "mycpanel", "cygnus", "exposure", "dc", "groups", "tickets", "nat", "test10",
    "contacts", "ds", "smtp1", "go", "minecraft", "service", "devel", "mysql2", "testsite", "design", "booking", "bookings", "mail5", "usb",
    "feeds", "wwp", "dev3", "managethisdomain", "siteadmin", "emails", "dp", "ftp10", "alan5", "slb", "vps1", "photo", "portfolio", "public",
    "joomla", "symccloud", "adsl", "cg", "controlp", "googleffffffffffa87e73", "project", "ldap", "dating", "vpn1", "saturn", "surveys", "sp",
    "wwwold", "jira", "drive", "wmail", "tracker", "extendcp", "ftpadmin", "www9", "links", "dms", "server3", "ebay", "radius", "wave", "uploads",
    "mail0", "events", "mailbackup", "cvs", "s", "s3", "trade", "dev4", "ntp0", "radio", "mailout", "mail01", "oma", "web3", "mailbox", "ping0",
    "mailing", "code", "webexpand", "net9design", "lync", "trac", "hbadmin", "vpscp", "act", "ex", "nas", "hotels", "campaign", "main", "conference",
    "demo2", "mailgate2", "private", "dom", "payments", "directory"
];

    $results = [];

    foreach ($subdomains as $sub) {
        $fullDomain = "$sub.$domain";
        try {
            $output = shell_exec("dig +short CNAME " . escapeshellarg($fullDomain));
            if (!empty(trim($output))) {
                $cname = trim($output);
                $parts = explode('.', $domain);
                $mainDomain = end($parts);

                if (strpos($cname, $mainDomain) === false) {
                    $pingOutput = shell_exec("ping -c 1 " . escapeshellarg($cname));
                    if (strpos($pingOutput, 'unreachable') !== false || strpos($pingOutput, 'timed out') !== false) {
                        $results[] = "<strong>$fullDomain</strong> | CNAME: <a href='https://$cname'>$cname</a> | Уязвимость возможна!";
                    } else {
                        $results[] = "<strong>$fullDomain</strong> | CNAME: <a href='https://$cname'>$cname</a>";
                    }
                }
            }
        } catch (Exception $e) {
            $results[] = "<strong>$fullDomain</strong> | Ошибка выполнения.";
        }
    }

    return !empty($results) ? implode("<br>", $results) : "Nothing found.";
}

function checkSameSiteScripting($domain) {
    // Проверяем, что домен корректен
    if (empty($domain)) {
        return "<p>Ошибка: Домен не указан.</p>";
    }

    // Формируем поддомен для проверки
    $subdomain = "localhost." . $domain;

    // Выполняем команду ping
    $command = "ping -c 1 " . escapeshellarg($subdomain) . " 2>&1";
    $output = shell_exec($command);

    // Анализируем результат
    if (
        strpos($output, '100% packet loss') === false && // Нет потери пакетов
        strpos($output, 'unreachable') === false &&      // Адрес недоступен
        strpos($output, 'Name or service not known') === false && // Ошибка DNS
        strpos($output, 'unknown host') === false       // Неизвестный хост
    ) {
        return "<h3 style='color:black;'> Уязвимость Same-Site Scripting:</h3><p>ping <strong>$subdomain</strong>  Reachable. Potential vulnerability!</p>";
    } else {
        return "<h3 style='color:black;'> Same-Site Scripting:</h3><p>ping <strong>$subdomain</strong> Not accessible. No vulnerability found.</p>";
    }
}

// Функция для проверки SSH-алгоритмов с помощью nmap
function checkSshAlgorithms($domain) {
    // Добавляем протокол, если его нет
    $target = strpos($domain, 'http') === false ? "https://$domain" : $domain;

    // Извлекаем хост из URL
    $parsed_url = parse_url($target);
    $host = $parsed_url['host'] ?? '';

    if (empty($host)) {
        return "<p>Ошибка: Не удалось определить хост для домена $domain.</p>";
    }

    // Проверяем наличие nmap
    $nmapPath = shell_exec('which nmap');
    if (empty(trim($nmapPath))) {
        return "<p>Ошибка: Nmap не установлен.</p>";
    }

    // Выполняем команду nmap для проверки SSH-алгоритмов
    $command = "nmap --script ssh2-enum-algos -sV -p 22 " . escapeshellarg($host) . " 2>&1";
    $output = shell_exec($command);

    if (empty(trim($output))) {
        return "<p>Ошибка: Nmap не вернул результатов для домена $domain.</p>";
    }

    // Анализируем результат
    if (strpos($output, '22/tcp filtered') !== false || strpos($output, 'closed') !== false) {
        return "<h3 style='color:black;'>Terpain Vulnerability Check::</h3><p>Port 22 is closed or filtered. No vulnerability detected.</p>";
    }

    if (strpos($output, 'ssh2-enum-algos') !== false) {
        return "<h3 style='color:black;'>SSH Algorithm Vulnerability:</h3><p>Active SSH algorithms detected. Potential vulnerability!</p><pre>" . htmlspecialchars($output) . "</pre>";
    }

    return "<h3 style='color:black;'>SSH Algorithm Check:</h3><p>No vulnerability detected.</p>";
}


function runNmapVulnScan($domain) {
    // Проверяем, что домен указан
    if (empty($domain)) {
        return "<p>Ошибка: Домен не указан.</p>";
    }

    // Проверяем наличие nmap
    $nmapPath = shell_exec('which nmap');
    if (empty(trim($nmapPath))) {
        return "<p>Ошибка: Nmap не установлен.</p>";
    }

    // Формируем команду для Nmap
    $command = "nmap -sV --script vuln " . escapeshellarg($domain) . " 2>&1";
    $output = shell_exec($command);

    // Проверяем, что вывод не пустой
    if (empty(trim($output))) {
        return "<p>Ошибка: Nmap не вернул результатов для домена $domain.</p>";
    }

    // Возвращаем результат
    return "<h3 style='color:black;'> Vulnerability Scan Results (Nmap):</h3><pre>" . htmlspecialchars($output) . "</pre>";
}

function runNiktoScan($domain) {
    // Проверяем, что домен указан
    if (empty($domain)) {
        return "<p>Ошибка: Домен не указан.</p>";
    }

    // Автоматически добавляем https://, если протокол не указан
    if (!preg_match('/^https?:\/\//', $domain)) {
        $url = "https://$domain";
    } else {
        $url = $domain;
    }

    // Проверяем наличие Nikto
    $niktoPath = trim(shell_exec('which nikto'));
    if (empty($niktoPath)) {
        return "<p>Ошибка: Nikto не установлен.</p>";
    }

    // Формируем команду для Nikto
    $command = "nikto -h " . escapeshellarg($url) . " -Tuning 23 2>&1";

    // Выполняем команду и получаем вывод
    $output = shell_exec($command);

    // Проверяем, что вывод не пустой
    if (empty(trim($output))) {
        return "<p>Nikto не вернул данных для домена $domain.</p>";
    }

    // Возвращаем результат
    return "<h3 style='color:black;'>Vulnerability Scan Results (Nikto):</h3><pre>" . htmlspecialchars($output) . "</pre>";
}


// Запуск всех сканеров
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['run_all_scans']) && !empty($domain)): ?>
    <div class="container" id="unified_results">
        <button class="copy-button" onclick="copyResults()">Copy to Clipboard</button>

        <h2 style="text-align:center; color:black;">Scan results for: <?= htmlspecialchars($domain) ?></h2>

        <h3 style="color:black;">Subdomains:</h3>
        <?= scanSubdomains($domain) ?>

        <h3 style="color:black;">Technologies used by the site (WhatWeb):</h3>
        <?= runWhatWeb($domain) ?>

        <h3 style="color:black;">Archived URLs (Wayback Machine):</h3>
        <?= getWaybackUrls($domain) ?>

        <h3 style="color:black;"> Directories:</h3>
        <?= checkDirectories($domain) ?>

        <h3 style="color:black;"> Nmap Port Scan:</h3>
        <?= runNmapScan($domain) ?>

        <h3 style="color:black;"> WAF Detection:</h3>
        <?= detectWaf($domain) ?>

        <h3 style="color:black;"> API Endpoints:</h3>
        <?= findApiEndpoints($domain) ?>
        
        <h3 style="color:black;"> Backup-files:</h3>
        <?= checkBackupFiles($domain) ?>
	
        <h3 style="color:black;">WHOIS information:</h3>
        <?= getWhoisInfo($domain) ?>

        <h3 style="color:black;">SSL Certificate:</h3>
        <?= getSSLCert($domain) ?>
        
        <h3 style="color:black;"></h3>
        <?= checkSecurityHeaders($domain) ?>
                
        <h3 style="color:black;">Check for Vulnerable TLS Ciphers:</h3>
        <?= checkTlsCiphers($domain) ?>
        
        <h3 style="color:black;">Subdomain Takeover: potentially vulnerable — requires manual verification. Check the hosting provider and see if you can re-register the domain under your control and upload your own content.</h3>
        <?= checkSubdomainTakeover($domain) ?>
        
        <h3 style="color:black;"></h3>
        <?= checkSameSiteScripting($domain) ?>
        
        <h3 style="color:black;"></h3>
        <?= checkSshAlgorithms($domain) ?>
        
        <h3 style="color:black;"></h3>
        <?= runNmapVulnScan($domain) ?>
        
	<h3 style="color:black;"></h3>
        <?= runNiktoScan($domain) ?>

        
    </div>
<?php endif; ?>

<script>
document.addEventListener("DOMContentLoaded", function () {
    const showAllButton = document.getElementById('show-all-urls');
    if (showAllButton) {
        showAllButton.addEventListener('click', function () {
            const hiddenUrls = document.querySelectorAll('.hidden-url');
            hiddenUrls.forEach(url => {
                url.style.display = 'list-item'; // Показываем скрытые элементы
            });
            showAllButton.style.display = 'none'; // Убираем кнопку после нажатия
        });
    }
});
</script>


<script>
    function copyResults() {
        var results = document.getElementById('unified_results').innerText;
        navigator.clipboard.writeText(results).then(() => {
            
        }).catch(err => {
            console.error('Не удалось скопировать текст: ', err);
        });
    }
</script>

</body>
</html>
