###############################################################################
# OpenVAS Vulnerability Test
#
# Directory Scanner
#
# Authors:
# H D Moore <hdm@digitaloffense.net>
#
# Copyright:
# Copyright (C) 2005 Digital Defense Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11032");
  script_version("2021-08-05T10:59:45+0000");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_xref(name:"OWASP", value:"OWASP-CM-006");
  script_name("Directory Scanner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Digital Defense Inc.");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl",
                      "global_settings.nasl", "gb_ssl_sni_supported.nasl"); # SNI support should be determined first
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_timeout(900);

  script_tag(name:"summary", value:"This plugin attempts to determine the presence of various
  common dirs on the remote web server");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("404.inc");
include("misc_func.inc");

debug = 0;

# this arrays contains the results
discoveredDirList = make_list();
authDirList = make_list();

cgi_dirs_exclude_pattern = get_kb_item( "global_settings/cgi_dirs_exclude_pattern" );
use_cgi_dirs_exclude_pattern = get_kb_item( "global_settings/use_cgi_dirs_exclude_pattern" );
cgi_dirs_exclude_servermanual = get_kb_item( "global_settings/cgi_dirs_exclude_servermanual" );

function check_cgi_dir( dir, port ) {

  local_var req, res, dir, port;

  req = http_get( item:dir + "/non-existent"  + rand(), port:port );
  res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );
  currReqs++;
  if( ! res )
    failedReqs++;

  if( res =~ "^HTTP/1\.[01] 404" ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

function add_discovered_list( dir, port, host ) {

  local_var dir, port, host, dir_key;

  if( ! in_array( search:dir, array:discoveredDirList ) ) {
    discoveredDirList = make_list( discoveredDirList, dir );

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    #TBD: Do a check_cgi_dir( dir:dir, port:port ); before?
    dir_key = "www/" + host + "/" + port + "/content/directories";
    if( debug ) display( "Setting KB key: ", dir_key, " to '", dir );
    set_kb_item( name:dir_key, value:dir );
  }
}

function add_auth_dir_list( dir, port, host, basic, realm ) {

  local_var dir, port, host, dir_key, basic, realm;

  if( ! in_array( search:dir, array:authDirList ) ) {

    authDirList = make_list( authDirList, dir );

    if( use_cgi_dirs_exclude_pattern ) {
      if( egrep( pattern:cgi_dirs_exclude_pattern, string:dir ) ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/excluded_directories", value:dir );
        return;
      }
    }

    set_kb_item( name:"www/content/auth_required", value:TRUE );
    dir_key = "www/" + host + "/" + port + "/content/auth_required";
    if( debug ) display( "Setting KB key: ", dir_key, " to '", dir );
    set_kb_item( name:dir_key, value:dir );

    # Used in 2018/gb_http_cleartext_creds_submit.nasl
    if( basic ) {
      set_kb_item( name:"www/basic_auth/detected", value:TRUE );
      set_kb_item( name:"www/pw_input_field_or_basic_auth/detected", value:TRUE );
      # Used in 2018/gb_http_cleartext_creds_submit.nasl
      set_kb_item( name:"www/" + host + "/" + port + "/content/basic_auth/" + dir, value:http_report_vuln_url( port:port, url:dir, url_only:TRUE ) + ":" + realm );
    }
  }
}

testDirList = make_list(
".cobalt",
".tools",
".tools/phpMyAdmin",
".tools/phpMyAdmin/current",
# https://ma.ttias.be/well-known-directory-webservers-aka-rfc-5785/
# https://tools.ietf.org/html/rfc5785
# http://sabre.io/dav/service-discovery/
# https://github.com/owncloud/core/blob/29570212c983f0293738dbb0132a5b562dcac9fa/.htaccess#L66-L69
".well-known",
".well-known/acme-challenge",
".well-known/caldav",
".well-known/carddav",
".well-known/host-meta",
".well-known/pki-validation",
".well-known/webfinger",
# git
".git",
".git/logs",
".git/info",
# Bazaar
".bzr",
# SVN
".svn",
# Mercurial
".hg",
# SSH homefolder
".ssh",
#
"1",
"10",
"2",
"3",
"4",
"5",
"6",
"7",
"8",
"9",
"3rdparty",
"3rdparty/phpMyAdmin",
"3rdparty/phpmyadmin",
"AdminWeb",
"Admin_files",
"Administration",
"AdvWebAdmin",
"Agent",
"Agents",
"Album",
"AlbumArt_",
"BizTalkTracking",
"BizTalkServerDocs",
"BizTalkServerRepository",
"Boutiques",
"Corporate",
"CS",
"CVS",
"DB4Web",
"DMR",
"DocuColor",
"DVWA",
"GXApp",
"HB",
"HBTemplates",
"IBMWebAS",
"Install",
"JBookIt",
"Log",
"Mail",
"MessagingManager",
"Msword",
"NSearch",
"NetDynamic",
"NetDynamics",
"News",
"PDG_Cart",
"PulseCMS",
"QConvergeConsole",
"RCS",
"README",
"ROADS",
"Readme",
"Remote",
"SilverStream",
"Stats",
"StoreDB",
"Templates",
"ToDo",
"WebBank",
"WebCalendar",
"WebDB",
"WebShop",
"WebTrend",
"Web_store",
"WSsamples",
"XSL",
"_ScriptLibrary",
"_backup",
"_derived",
"_errors",
"_fpclass",
"_mem_bin",
"_notes",
"_objects",
"_old",
"_pages",
"_passwords",
"_private",
"_scripts",
"_sharedtemplates",
"_tests",
"_themes",
"_vti_bin",
"_vti_bot",
"_vti_log",
"_vti_pvt",
"_vti_shm",
"_vti_txt",
"a",
"about",
"acceso",
"access",
"accesswatch",
"acciones",
"account",
"accounting",
"activex",
"adm",
"admcgi",
"admentor",
"admin_",
"admin",
"admin.back",
"admin-bak",
"adminer",
"administration",
"administrator",
"admin-old",
"adminuser",
"adminweb",
"admisapi",
"agentes",
"analog",
"analytics",
"anthill",
"apache",
"api",
"app",
"applets",
"application",
"applications",
"apps",
"ar",
"archive",
"archives",
"asp",
"aspx",
"atc",
"auth",
"authadmin",
"aw",
"ayuda",
"b",
"b2-include",
"back",
"backend",
"backup",
"backups",
"bak",
"banca",
"banco",
"bank",
"banner",
"banner01",
"banners",
"batch",
"bb-dnbd",
"bbv",
"bdata",
"bdatos",
"beta",
"billpay",
"bin",
"blog",
"boadmin",
"board",
"boot",
"btauxdir",
"bug",
"bugs",
"bugzilla",
"business",
"buy",
"buynow",
"c",
"cache-stats",
"cacti",
"caja",
"card",
"cards",
"cart",
"cash",
"caspsamp",
"catalog",
"cbi-bin",
"ccard",
"ccards",
"cd",
"cd-cgi",
"cdrom",
"ce_html",
"cert",
"certificado",
"certificate",
"cfappman",
"cfdocs",
"cfide",
"cgi",
"cgi-auth",
"cgi-bin",
"cgibin",
"cgi-bin2",
"cgi-csc",
"cgi-lib",
"cgilib",
"cgi-local",
"cgis",
"cgi-scripts",
"cgiscripts",
"cgi-shl",
"cgi-shop",
"cgi-sys",
"cgi-weddico",
"cgi-win",
"cgiwin",
"chat",
"class",
"classes",
"client",
"cliente",
"clientes",
"cm",
"cms",
"cmsample",
"cobalt-images",
"code",
"comments",
"common",
"communicator",
"community",
"company",
"compra",
"compras",
"compressed",
"conecta",
"conf",
"config",
"connect",
"console",
"content",
"controlpanel",
"core",
"corp",
"correo",
"counter",
"credit",
"cron",
"crons",
"crypto",
"csr",
"css",
"cuenta",
"cuentas",
"currency",
"customers",
"cvsweb",
"cybercash",
"d",
"darkportal",
"dashboard",
"dat",
"data",
"database",
"databases",
"datafiles",
"dato",
"datos",
"dav",
"db",
"dbase",
"dcforum",
"ddreport",
"ddrint",
"demo",
"demoauct",
"demomall",
"demos",
"design",
"dev",
"devel",
"development",
"dialup",
"dialup_admin",
"dir",
"directory",
"directorymanager",
"dl",
"dll",
"dm",
"dms",
"dms0",
"dmsdump",
"doc",
"doc1",
"doc-html",
"docs",
"docs1",
"document",
"documents",
"down",
"download",
"downloads",
"drupal",
"drupal6",
"drupal7",
"dspam",
"dump",
"durep",
"e",
"easylog",
"eforum",
"egroupware",
"ejemplo",
"ejemplos",
"email",
"emailclass",
"eManager",
"employees",
"empoyees",
"empris",
"envia",
"enviamail",
"error",
"errors",
"es",
"estmt",
"etc",
"example",
"examples",
"exc",
"excel",
"exchange",
"exe",
"exec",
"export",
"external",
"f",
"fbsd",
"fcgi-bin",
"file",
"filemanager",
"files",
"flexcube@",
"flexcubeat",
"foldoc",
"form",
"formalms",
"forms",
"formsmgr",
"form-totaller",
"forum",
"forums",
"foto",
"fotos",
"fpadmin",
"fpdb",
"fpsample",
"frameset",
"framesets",
"ftp",
"ftproot",
"g",
"ganglia",
"gfx",
"global",
"gosa",
"grocery",
"guest",
"guestbook",
"guests",
"help",
"helpdesk",
"hidden",
"hide",
"hitmatic",
"hit_tracker",
"hlstats",
"home",
"horde",
"hostingcontroller",
"howto",
"hr",
"hrm",
"ht",
"htbin",
"htdocs",
"html",
"hyperstat",
"ibank",
"ibill",
"icingaweb2",
"icons",
"idea",
"ideas",
"iisadmin",
"iisprotect",
"iissamples",
"ikiwiki",
"image",
"imagenes",
"imagery",
"images",
"img",
"imp",
"import",
"impreso",
"inc",
"include",
"includes",
"incoming",
"info",
"information",
"ingresa",
"ingreso",
"install",
"internal",
"intranet",
"inventory",
"invitado",
"isapi",
"japidoc",
"java",
"javascript",
"javasdk",
"javatest",
"jave",
"jdbc",
"job",
"jrun",
"js",
"jserv",
"jslib",
"jsp",
"junk",
"keyserver",
"kibana",
"kiva",
"labs",
"lam",
"laravel",
"lcgi",
"ldap",
"ldapadmin",
"ldapadmin/htdocs",
"leap",
"legal",
"lib",
"libraries",
"library",
"libro",
"links",
"linux",
"loader",
"log",
"logfile",
"logfiles",
"logg",
"logger",
"logging",
"login",
"logon",
"logs",
"lost+found",
"m",
"mail",
"mail_log_files",
"mailman",
"mailroot",
"makefile",
"mall_log_files",
"manage",
"manual",
"marketing",
"matomo",
"member",
"members",
"mercuryboard",
"message",
"messaging",
"metacart",
"misc",
"mkstats",
"movimientos",
"mp3",
"mp3s",
"mqseries",
"msql",
"myaccount",
"mysql",
"mysql_admin",
"ncadmin",
"nchelp",
"ncsample",
"nds",
"netbasic",
"netcat",
"netmagstats",
"netscape",
"netshare",
"nettracker",
"new",
"nextgeneration",
"nl",
"noticias",
"obj",
"objects",
"odbc",
"offers",
"ojs",
"old",
"old_files",
"oldfiles",
"oprocmgr-service",
"oprocmgr-status",
"oracle",
"oradata",
"order",
"orders",
"otrs",
"otrs-web",
"outgoing",
"owncloud",
"owners",
"pages",
"panel",
"passport",
"password",
"passwords",
"payment",
"payments",
"pccsmysqladm",
"perl",
"perl5",
"perl-status",
"personal",
"personal_pages",
"pforum",
"phorum",
"php",
"phpBB",
"php_classes",
"phpclassifieds",
"phpimageview",
"phpip",
"phpldapadmin",
"phpldapadmin/htdocs",
"phpmyadmin",
"phpMyAdmin",
"PHPMyAdmin",
"phpnuke",
"phppgadmin",
"phpPhotoAlbum",
"phpprojekt",
"phpSecurePages",
"phpunit",
"piranha",
"piwik",
"pls",
"pma",
"poll",
"polls",
"portal",
"postgres",
"ppwb",
"printers",
"priv",
"privado",
"private",
"prod",
"protected",
"prueba",
"pruebas",
"prv",
"pub",
"public",
"publica",
"publicar",
"publico",
"publish",
"pulsecms",
"purchase",
"purchases",
"pw",
"random_banner",
"rdp",
"redmine",
"register",
"registered",
"rem",
"report",
"reports",
"reseller",
"restricted",
"retail",
"reviews",
"root",
"roundcube",
"roundcubemail",
"rsrc",
"sales",
"sample",
"samples",
"save",
"script",
"scripts",
"search",
"search97",
"search-ui",
"secret",
"secure",
"secured",
"sell",
"serve",
"server-info",
"servers",
"server_stats",
"serverstats",
"server-status",
"service",
"services",
"servicio",
"servicios",
"servlet",
"servlets",
"session",
"setup",
"share",
"shared",
"shell-cgi",
"shipping",
"shop",
"shopper",
"shopping",
"site",
"siteadmin",
"sitebuildercontent",
"sitebuilderfiles",
"sitebuilderpictures",
"sitemgr",
"siteminder",
"siteminderagent",
"sites",
"siteserver",
"sitestats",
"siteupdate",
"slide",
"smreports",
"smreportsviewer",
"soap",
"soapdocs",
"software",
"solaris",
"solutions",
"source",
"sql",
"squid",
"squirrelmail",
"src",
"srchadm",
"ssi",
"ssl",
"sslkeys",
"staff",
"stag",
"stage",
"staging",
"stat",
"statistic",
"statistics",
"statistik",
"statistiken",
"stats",
"stats-bin-p",
"stats_old",
"status",
"storage",
"store",
"storemgr",
"stronghold-info",
"stronghold-status",
"stuff",
"style",
"styles",
"stylesheet",
"stylesheets",
"subir",
"sun",
"super_stats",
"support",
"supporter",
"sys",
"sysadmin",
"sysbackup",
"system",
"tar",
"tarantella",
"tarjetas",
"tdbin",
"tech",
"technote",
"te_html",
"temp",
"template",
"templates",
"temporal",
"test",
"test-cgi",
"testing",
"tests",
"testweb",
"ticket",
"tickets",
"tiki",
"tikiwiki",
"tmp",
"tools",
"tpv",
"trabajo",
"trac",
"track",
"tracking",
"transito",
"transpolar",
"tree",
"trees",
"twiki",
"uapi-cgi",
"uapi-cgi/admin",
"ucs-overview",
"univention-management-console",
"updates",
"upload",
"uploads",
"us",
"usage",
"user",
"userdb",
"users",
"usr",
"ustats",
"usuario",
"usuarios",
"util",
"utils",
"v4",
"vendor",
"vfs",
"w3perl",
"w-agora",
"way-board",
"web",
"web800fo",
"webadmin",
"webalizer",
# <-- e.g. Zarafa
"webaccess",
"webapp",
# -->
"webapps",
"webboard",
"webcart",
"webcart-lite",
"webdata",
"webdav",
"webdb",
"webimages",
"webimages2",
"weblog",
"weblogs",
"webmail",
"webmaster",
"webmaster_logs",
"webMathematica",
"webpub",
"webpub-ui",
"webreports",
"webreps",
"webshare",
"website",
"webstat",
"webstats",
"webtrace",
"webtrends",
"web_usage",
"wiki",
"windows",
"word",
"work",
"workspace",
"wsdocs",
"wstats",
"wusage",
"www",
"wwwjoin",
"wwwlog",
"www-sql",
"wwwstat",
"wwwstats",
"xampp",
"xGB",
"xml",
"xtemp",
"zabbix",
"zb41",
"zipfiles",
"~1",
"~admin",
"~log",
"~root",
"~stats",
"~webstats",
"~wsdocs",
# The three following directories exist on Resin default installation
"faq",
"ref",
"cmp",
# Phishing
"cgi-bim",
# Lite-serve
"cgi-isapi",
# HyperWave
"wavemaster.internal",
# Urchin
"urchin",
"urchin3",
"urchin5",
# CVE-2000-0237
"publisher",
# Common Locale
"en",
"en-US",
"fr",
"intl",
# Sympa
"wws",
"wwsympa",
"sympa",
# Opentaps and Apache OFBiz
"accounting/control/main",
"ap/control/main",
"ar/control/main",
"assetmaint/control/main",
"bi/control/main",
"birt/control/main",
"catalog/control/main",
"cmssite/control/main",
"content/control/main",
"control/main",
"crmsfa/control/main",
"ebay/control/main",
"ebaystore/control/main",
"ecommerce/control/main",
"ecomseo", # nb: special case
"example/control/main",
"exampleext/control/main",
"facility/control/main",
"financials/control/main",
"googlebase/control/main",
"hhfacility/control/main",
"humanres/control/main",
"ldap/control/main",
"lucence/control/main",
"manufacturing/control/main",
"marketing/control/main",
"msggateway/control/main",
"multiflex/control/main",
"myportal/control/main",
"ofbizsetup/control/main",
"ordermgr/control/main",
"passport/control/main",
"partymgr/control/main",
"pricat/control/main",
"projectmgr/control/main",
"purchasing/control/main",
"scrum/control/main",
"sfa/control/main",
"sofami/control/main",
"solr/control/main",
"warehouse/control/main",
"webpos/control/main",
"webtools/control/main",
"workeffort/control/main",
# GVM / GSA related URLs
# "css", nb: Already existing above, still keeping as comments
# "help",
# "img",
# "js",
# "login",
"gmp",
"locales",
"omp",
"static",
"static/img",
"static/js",
"static/css",
"system_report",
# Fortinet FortiOS SSL VPN Web Portal
"remote",
# Collabora Online Development Edition / LibreOffice Online
"hosting",
"hosting/discovery",
"hosting/capabilities",
"lool",
"lool/adminws",
"loleaflet",
"loleaflet/dist",
"loleaflet/dist/admin",
"dist",
"dist/admin",
# e.g. Metasploitable2 VM
"dvwa",
"mutillidae",
# ownCloud
"updater",
"ocs-provider",
"ocm-provider", #nb: OpenCloudMesh Endpoint
# Kibana
"app/kibana", #nb: "/app" is already included above
"spaces",
"spaces/enter",
# Samsung Q60 series smart TV but might exist for other products / applications as well
"ws",
"ws/auth",
"ws/pairing",
"ws/debug",
# nb: Only api/v2 existed for the samsung device but those seems to be quite common endpoints
# like seen in some other VTs in the feed.
"api/v1",
"api/v1.0",
"api/v2",
"api/v2.0",
"api/v3",
"api/v3.0",
"api/v4",
"api/v4.0",
"api/v5",
"api/v5.0",
# Cisco UCS Director
"app/ui", #nb: "app" is already included above
# Juniper and Pulse Connect SSL-VPN
"dana-na",
"dana-na/auth",
"dana-na/download",
"dana-na/meeting",
"dana",
"dana/fb",
"dana/fb/smb",
"dana-cached",
"dana-cached/sc",
"dana-cached/setup",
# Citrix ADC / Gateway
"vpn",
"vpn/js",
"vpns",
"vpns/cfg",
"vpns/portal",
"vpns/portal/scripts",
# WordPress Core dirs
"wp-admin",
"wp-content",
"wp-content/gallery",
"wp-content/languages",
"wp-content/plugins",
"wp-content/themes",
"wp-content/upgrade",
"wp-content/uploads",
"wp-includes",
"wp-json", # Pretty links
"index.php/wp-json", # Non-Pretty links
"wordpress/wp-admin",
"wordpress/wp-content",
"wordpress/wp-content/gallery",
"wordpress/wp-content/languages",
"wordpress/wp-content/plugins",
"wordpress/wp-content/themes",
"wordpress/wp-content/upgrade",
"wordpress/wp-content/uploads",
"wordpress/wp-includes",
"wordpress/wp-json",
"wordpress/index.php/wp-json",
"wp/wp-admin",
"wp/wp-content",
"wp/wp-content/gallery",
"wp/wp-content/languages",
"wp/wp-content/plugins",
"wp/wp-content/themes",
"wp/wp-content/upgrade",
"wp/wp-content/uploads",
"wp/wp-includes",
"wp/wp-json",
"wp/index.php/wp-json",
"blog/wp-admin",
"blog/wp-content",
"blog/wp-content/gallery",
"blog/wp-content/languages",
"blog/wp-content/plugins",
"blog/wp-content/themes",
"blog/wp-content/upgrade",
"blog/wp-content/uploads",
"blog/wp-includes",
"blog/wp-json",
"blog/index.php/wp-json",
# WordPress plugins dirs
"wp-content/backup-db",
"wp-content/backups-dup-pro",
"wp-content/backups-dup-lite",
"wp-content/updraft",
"wp-content/w3tc-config",
"wordpress/wp-content/backup-db",
"wordpress/wp-content/backups-dup-pro",
"wordpress/wp-content/backups-dup-lite",
"wordpress/wp-content/updraft",
"wordpress/wp-content/w3tc-config",
"wp/wp-content/backup-db",
"wp/wp-content/backups-dup-pro",
"wp/wp-content/backups-dup-lite",
"wp/wp-content/updraft",
"wp/wp-content/w3tc-config",
"blog/wp-content/backup-db",
"blog/wp-content/backups-dup-pro",
"blog/wp-content/backups-dup-lite",
"blog/wp-content/updraft",
"blog/wp-content/w3tc-config",
# Cloudflare, see e.g. https://seclists.org/nmap-dev/2019/q1/42
"cdn-cgi",
"cdn-cgi/apps",
"cdn-cgi/apps/head",
"cdn-cgi/scripts",
"cdn-cgi/pe",
# Trend Micro Apex Central (this has /webapp which is already included above).
"ControlManager",
# Sophos XG Firewall
"userportal",
"userportal/webpages",
"userportal/webpages/myaccount",
"webconsole",
"webconsole/webpages",
# Outlook Web App
"owa",
"owa/auth",
# Laravel Telescope
"telescope",
# Apache Solr
"solr",
"apachesolr",
# e.g. SpinetiX Fusion
"fusion",
"content",
"content/files",
"content/files/backups",
# Oracle BI Publisher
"xmlpserver",
# RUCKUS IoT Controller
"refUI",
# Config dir of various apps / frameworks like Symfony
"app/config",
# Citrix Endpoint Management or XenMobile Server
"zdm",
# Cisco Security Manager, possible other products as well
"CSCOnm",
"CSCOnm/servlet",
"CSCOnm/servlet/login",
"cwhp",
"cwhp/CSMSDesktop",
"athena",
"athena/xdmProxy",
"athena/itf",
# Cisco Webex Meetings Server
"orion",
"webappng",
"webappng/sites",
"webappng/sites/meetings",
"webappng/sites/meetings/dashboard",
# Tomcat
"tomcat-docs", #nb: Will be ignored by default
"manager",
"manager/html",
"manager/status",
"host-manager",
"host-manager/html",
"tomcat",
"tomcat/manager",
"tomcat/manager/html",
"admin-console",
"web-console",
"web-console/Invoker",
"jmx-console",
"jmx-console/HtmlAdaptor",
"invoker",
"invoker/JMXInvokerServlet",
"cognos_express",
"cognos_express/manager",
"cognos_express/manager/html",
# D-Link DSR devices
"scgi-bin",
# Micro Focus (Novell) Filr
"filr",
"ssf",
"ssf/a",
"rest",
# AWStats
"awstats",
"awstats/cgi-bin",
"awstats-cgi",
# WD My Cloud
"nas",
"nas/v1",
"xml",
"web",
"web/images",
"web/function",
"web/restSDK",
"web/restAPI",
"web/ota",
"api",
"api/2.1",
"api/2.1/rest",
# Various application servers like Apache Tomcat or Mortbay Jetty. Normally these should prevent the
# direct access to the directory but we're checking it anyway if there are any mis-configurations in place.
"WEB-INF",
"WEB-INF/classes",
"WEB-INF/lib",
"META-INF",
# WildFly H2 Console
"h2console",
"h2console/console",
# Liferay Portal
"api",
"api/jsonws",
# VMware Identity Manager / vRealize Automation
"SAAS",
"SAAS/WEB-INF",
"SAAS/META-INF",
# Novell Web Manager
"WebAdmin",
# Unknown product related to Apache Cocoon
"v2",
"v2/api",
"v2/api/product",
"v2/api/product/manger",
"v2/api/product/manager", # nb: The above endpoint might be a typo so both are used.
# VMware vSphere Client of vCenter Server
"ui",
"ui/resources",
"ui/resources/libs",
"ui/resources/js",
"ui/resources/css",
"ui/resources/ng-next-app",
"ui/resources/ng-next-app/styles",
"ui/resources/ui",
"ui/resources/ui/views",
"ui/resources/ui/views/mainlayout",
"ui/modules-join-files",
"ui/modules-join-files/js",
"ui/modules-join-files/css",
"ui/modules-proxy-lib",
"ui/modules-proxy-lib/resources",
"ui/modules-proxy-lib/resources/js",
"ui/psc-ui",
"ui/psc-ui/resources",
"ui/psc-ui/resources/js",
"ui/dashboard-lite-ui",
"ui/dashboard-lite-ui/resources",
"ui/dashboard-lite-ui/resources/js",
"ui/certificate-ui",
"ui/certificate-ui/resources",
"ui/certificate-ui/resources/js",
"ui/advperfcharts-ui",
"ui/advperfcharts-ui/resources",
"ui/advperfcharts-ui/resources/js",
"ui/h5-vsan",
"ui/h5-vsan/rest",
"ui/h5-vsan/rest/proxy",
"ui/h5-vsan/rest/proxy/service",
"ui/h5-vsan/rest/proxy/service/CLASS",
"sdk",
"cache",
"vsphere-client",
"history",
"assets",
"websso",
"websso/SAML2",
"websso/SAML2/SSO",
"websso/resources",
"websso/resources/js",
"websso/resources/js/assets",
"websso/resources/img",
"websso/resources/css",
"ui/vropspluginui",
"ui/vropspluginui/rest",
"ui/vropspluginui/rest/services",
"ui/vropspluginui/rest/services/getstatus", # nb: This and the previous is an API endpoint which was unprotected before the patch from VMSA-2021-0002
"statsreport",
# VMware vRealize Operations Manager
"admin",
"ui",
"suite-api",
"suite-api/api",
"suite-api/api/versions",
"casa",
"casa/nodes",
# RedHat Stronghold
"stronghold-info",
"stronghold-status",
# Resin
"caucho-status",
# Enterasys Dragon Enterprise Reporting
"dragon",
# HP Systems Insight Manager
"simsearch",
"simsearch/messagebroker",
"mxportal",
"mxportal/taskandjob",
# Inspur ClusterEngine
"module",
"module/login",
# AfterLogic Aurora/WebMail
"afterlogic",
"aurora",
"webmail",
"webmailpro",
# NetApp Cloud Manager
"occmui",
"occm",
"occm/api",
"occm/api/occm",
"occm/api/occm/system",
# Adobe ColdFusion
"CFIDE",
"CFIDE/administrator",
"CFIDE/administrator/settings",
"CFIDE/administrator/help",
"CFIDE/adminapi",
"CFIDE/services",
"cf_scripts",
"cf_scripts/scripts",
"cf_scripts/scripts/ajax",
"cf_scripts/scripts/ajax/package",
"cf-scripts",
"cf-scripts/scripts",
"cf-scripts/scripts/ajax",
"cf-scripts/scripts/ajax/package",
"CFIDE/scripts",
"CFIDE/scripts/ajax",
"CFIDE/scripts/ajax/package",
"cfide",
"cfide/scripts",
"cfide/scripts/ajax",
"cfide/scripts/ajax/package",
"CF_SFSD",
"CF_SFSD/scripts",
"CF_SFSD/scripts/ajax",
"CF_SFSD/scripts/ajax/package",
"cfide-scripts",
"cfide-scripts/ajax",
"cfide-scripts/ajax/package",
"cfmx",
"cfmx/CFIDE",
"cfmx/CFIDE/scripts",
"cfmx/CFIDE/scripts/ajax",
"cfmx/CFIDE/scripts/ajax/package",
# Proxmox Virtual Environment (VE, PVE)
"pve2",
"pve2/images",
"pve2/ext6",
"pve2/ext6/locale",
"pve2/ext6/theme-crisp",
"pve2/ext6/theme-crisp/resources",
"pve2/ext6/crisp",
"pve2/ext6/crisp/resources",
"pve2/fa",
"pve2/fa/css",
"pve2/css",
"pve2/js",
"pwt/css",
# SAP NetWeaver Portal
"irj",
"irj/portal",
"irj/servlet",
"irj/servlet/prt",
"irj/servlet/prt/portal",
"irj/servlet/prt/portal/prtroot",
"portal/irj",
"portal/irj/portal",
"portal/irj/servlet",
"portal/irj/servlet/prt",
"portal/irj/servlet/prt/portal",
"portal/irj/servlet/prt/portal/prtroot",
# Apache Struts
"struts",
"struts2-showcase",
"struts2-showcase/integration",
"struts2-showcase/skill",
"struts2-showcase/validation",
"struts2-showcase/config-browser",
"struts2-blank",
"struts2-blank/example",
"struts2-basic",
"struts2-mailreader",
"struts2-portlet",
"struts2-rest-showcase",
"struts2-rest-showcase/orders",
"struts-cookbook",
"struts-examples",
# VMware Workspace ONE Access / VMware Identity Manager
"cfg",
"hc",
# Ivanti Avalanche
"AvalancheWeb",
# VMware Workspace ONE UEM
"AirWatch",
# Used by an unknown scanner checking for Laravel ".env" files
"app",
"apps",
"assets",
"config",
"core",
"core/app",
"core/Database",
"cron",
"cronlab",
"database",
"lab",
"lib",
"vendor",
# Oracle E-Business Suite
"OA_HTML",
# Sun/Oracle Web Server
"admingui",
"admingui/version",
# SAP XML Data Archiving Service on SAP AS Java
"DataArchivingService",
"DataArchivingService/webcontent",
"DataArchivingService/webcontent/cas",
"DataArchivingService/webcontent/aas",
# Pega Infinity
"prweb",
"prweb/app",
"prweb/app/default",
"prweb/PRAuth",
"prweb/PRAuth/app",
"prweb/PRAuth/app/default",
"prweb/PRAuth/SSO",
# FLIR AX8
"FLIR",
"FLIR/usr",
"FLIR/usr/www",
"FLIR/usr/www/application",
"FLIR/usr/www/application/controller",
"camera",
"home",
"login",
"public",
"settings",
"storage",
# Cisco HyperFlex Connect
"hx",
"hx/api",
"upload",
# Self Service Password [LDAP Tool Box (LTB)]
"ssp",
"ssp/rest",
"ssp/rest/v1",
"ssp/rest/v2",
"rest",
"rest/v1",
"rest/v2",
# SolarWinds Orion Platform (e.g. NPM)
"Orion",
# HP / H3C iMC
"imc",
"imc/javax.faces.resource",
# Zend Framework config file location
"application",
"application/configs",
"configs",
# Apache Airflow
"admin",
"admin/login",
"admin/airflow",
"admin/airflow/login",
"aws_mwaa",
"aws_mwaa/login",
"airflow",
# ConcatServlet of Eclipse Jetty
"concat?",
# Unknown servlet of Eclipse Jetty
"static?",
# Mentioned as a directory in https://github.com/eclipse/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5
"context",
# Maipu Network devices
"php",
"php/common",
"webui",
# Akkadian Provisioning Manager
"pme",
"pme/database",
"pme/database/pme",
"pme/media",
"pme/backups",
# Lucee
"lucee",
"lucee/admin",
# FanRuan FineReport
"FineReport",
"FineReport/decision",
"WebReport",
"WebReport/decision",
"webroot",
"webroot/decision",
# SAP Web Dispatcher
"sap",
"sap/wdisp",
"sap/wdisp/admin",
"sap/wdisp/admin/icp",
"sap/wdisp/admin/public",
"sap/wdisp/admin/public/resources",
"sap/wdisp/admin/publicicp",
# VICIdial
"agc",
"agc3",
"vicidial",
"vicidial/agent_reports",
# Acronis Cyber Protect
"idp",
"idp/authorize",
"am",
"am/api",
"am/api/1",
"am/api/2",
"api",
"api/1",
"api/2",
"backup-console",
# FCKeditor / CKEditor
"fckeditor",
"editor",
"admin/fckeditor",
"sites/all/modules/fckeditor",
"resources/fckeditor",
"clientscript/fckeditor",
"wp-content/plugins/fckeditor-for-wordpress/fckeditor",
"FCKeditor",
"inc/fckeditor",
"includes/fckeditor",
"include/fckeditor",
"modules/fckeditor",
"plugins/fckeditor",
"HTMLEditor",
"admin/htmleditor",
"sites/all/modules/fckeditor/fckeditor",
"ckeditor",
"admin/ckeditor",
"sites/all/modules/ckeditor",
"resources/ckeditor",
"clientscript/ckeditor",
"wp-content/plugins/ckeditor-for-wordpress/ckeditor",
"vendor/plugins/fckeditor/public/javascripts",
"extensions/FCKeditor",
"extensions/FCKeditor/fckeditor",
# Huawei Home Gateway
"api",
"api/system",
"lib",
"html",
"lang",
# Cisco ASA / ASDM
"+CSCOT+",
"+CSCOE+",
"+CSCOE+/files",
"+CSCOE+/saml",
"+CSCOE+/saml/sp",
"+CSCOE+/sdesktop",
"+CSCOU+",
"+webvpn+",
"admin",
"admin/public",
"CACHE",
"CACHE/sdesktop",
"CACHE/sdesktop/install",
"CACHE/sdesktop/install/binaries",
"CSCOSSLC",
# W-Agora
"w-agora",
"cms",
# Online Grades
"grades",
"onlinegrades",
# Adobe Experience Manager (AEM)
"libs",
"libs/granite",
"libs/granite/core",
"libs/granite/core/content",
"system",
"system/console",
"system/sling",
"system/sling/cqform",
"crx",
"crx/de",
"crx/packmgr",
"etc",
"etc/clientlibs",
"etc/clientlibs/granite",
"etc/designs",
"content",
"content/dam",
"etc.clientlibs",
"etc.clientlibs/clientlibs",
"etc.clientlibs/clientlibs/granite",
# Prometheus
"alerts",
"graph",
"status",
"flags",
"config",
"rules",
"targets",
"tsdb-status",
"service-discovery",
"api",
"api/v1",
"api/v1/status",
# Some known JavaServer Faces (JSF2) apps / endpoints
"costModule",
"costModule/faces",
"faces",
"secureader",
"myaccount",
"SupportPortlet",
"SupportPortlet/faces",
"javax.faces.resource",
# Veeam Backup Enterprise Manager
"scripts",
"scripts/build",
"scripts/build/production",
"scripts/build/production/MainApp",
# OpenAM, MITREid Connect and other OAuth related products
"openam",
"OpenAM",
"opensso",
"sso",
"openam/.well-known",
"OpenAM/.well-known",
"opensso/.well-known",
"sso/.well-known",
"openam/.well-known/webfinger",
"OpenAM/.well-known/webfinger",
"opensso/.well-known/webfinger",
"sso/.well-known/webfinger",
"connect",
"connect/register",
"oauth",
"oauth/token",
"oauth/confirm_acces",
"openid-connect-server-webapp",
"openid-connect-server-webapp/register",
"openid-connect-server-webapp/api",
"openid-connect-server-webapp/api/clients",
"authorize",
# Circontrol CirCarLife / OCPP
"html",
"html/MainFrame",
"html/app",
"html/app/controllers",
"html/app/directives",
"html/app/partials",
"html/app/services",
"html/app/views",
"html/device-id",
"html/libs",
"html/log",
"html/repository",
"html/resources",
"html5",
"services",
"services/cmd",
"services/config",
"services/logs",
"services/logs/system_logs",
"services/system",
"services/user",
# WD My Book Live
"UI",
# LISTSERV Maestro
"lui",
"hub",
# Appnitro MachForm
"machform",
# IBM Maximo
"maximo",
"maximo/webclient",
"maximo/weblcient/login",
"meaweb",
"meaweb/os",
# IceWarp Mail Server
"webmail",
"webmail/basic",
# Kaseya VSA
"vsapres",
"vsapres/web20",
"vsapres/web20/core",
"vsapres/js",
"vsapres/js/thirdparty",
"vsapres/js/thirdparty/material",
"vsapres/assets",
"vsapres/assets/css",
"vsapres/js",
"vsapres/js/kaseya",
"vsapres/js/kaseya/web",
"vsapres/js/kaseya/web/Helpers",
"vsapres/images",
"vsapres/images/common",
"themes",
"themes/default",
"themes/default/images",
# Dell Wyse Management Suite
"ccm-web",
"ccm-web/admin",
"ccm-web/image",
# Seagate BlackArmor NAS
"backupmgt",
"admin",
# osCommerce
"osc",
"oscommerce",
"store",
"catalog",
"shop",
# MagicFlow
"msa",
# KevinLAB products (4st Solar, EMS, BEMS, HEMS) but also possible others
"http",
"dashboard",
"pages",
"modules",
"login",
"res",
# A few from 2021/gb_generic_http_web_dirs_dir_trav.nasl
"loginLess", # MERCUSYS Mercury X18G
"downloads", # Gate One
"public", # st module for Node.js
"static", # Node.js
"_next", # ZEIT Next.js
"node_modules", # node-srv node module
# Sage X3
"auth",
"auth/sage-id",
"auth/login",
"auth/login/page",
"auth/forgetMe",
"syracuse-auth",
"syracuse-auth/html",
# IBM Web Content Manager
"wps",
"wps/wcm",
"wps/wcm/webinterface",
"wps/wcm/webinterface/login",
# Orbis CMS
"orbis",
"orbis/admin",
"Orbis",
"Orbis/admin",
# DynPage CMS
"dynpage",
# BaconMap
"baconmap",
"baconmap/admin",
"map",
"map/admin",
# Node RED Dashboard
"ui_base",
"ui_base/js",
# qdPM
"core",
"core/config",
# PHP MicroCMS
"microcms" );

# Add domain name parts, create_hostname_parts_list() always returns a list, even an empty one
hnlist = create_hostname_parts_list();
testDirList = make_list( testDirList, hnlist );

if( debug ) display( "::[ DDI Directory Scanner running in debug mode ]::" );

fake404 = string("");
Check200 = TRUE;
Check401 = TRUE;
Check403 = TRUE;
CheckRedirect = TRUE;

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( debug ) display( ":: Checking directories on Hostname/IP:port " + host + ":" + port + "..." );

if( http_get_is_marked_broken( port:port, host:host ) )
  exit( 0 );

# counter for current failed requests
failedReqs = 0;
# counter for the current amount of done requests
currReqs = 0;
# counter for max failed requests
# The NVT will exit if this is reached
# TBD: Make this configurable?
maxFailedReqs = 3;

# pull the robots.txt file
if( debug ) display( ":: Checking for robots.txt..." );
res = http_get_cache( item:"/robots.txt", port:port );
currReqs++;
if( ! res )
  failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" && res =~ "Content-Type\s*:\s*text/plain" ) {

  body = http_extract_body_from_response( data:res );
  body = chomp( body );
  if( body ) {

    strings = split( body );

    foreach string( strings ) {

      if( egrep( pattern:"^\s*(dis)?allow\s*:.*/", string:string, icase:TRUE ) &&
          ! egrep( pattern:"^\s*(dis)?allow\s*:.*\.", string:string, icase:TRUE ) ) {

        # yes, i suck at regex's in nasl. I want my \s+!
        robot_dir = ereg_replace( pattern:"(dis)?allow\s*:\W*/(.*)$", string:string, replace:"\2", icase:TRUE );
        robot_dir = ereg_replace( pattern:"\W*$", string:robot_dir, replace:"", icase:TRUE );
        robot_dir = ereg_replace( pattern:"/$|\?$", string:robot_dir, replace:"", icase:TRUE );

        if( robot_dir != '' ) {
          testDirList = make_list( testDirList, robot_dir );
          if( debug ) display(":: Directory '", robot_dir, "' added to test list");
        }
      }
    }
  }
}

# pull the CVS/Entries file
if( debug ) display( ":: Checking for /CVS/Entries..." );
res = http_get_cache( item:"/CVS/Entries", port:port );
currReqs++;
if( ! res )
  failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  body = http_extract_body_from_response( data:res );
  body = chomp( body );
  if( body ) {

    strings = split( body, string( "\n" ) );

    foreach string( strings ) {

      if( egrep( pattern:"^D/(.+)/.*/.*/.*/.*", string:string, icase:FALSE ) ) {

        cvs_dir = ereg_replace( pattern:"^D/(.+)/.*/.*/.*/.*", string:string, replace:"\1", icase:FALSE );
        if( cvs_dir != '' ) {
          testDirList = make_list( testDirList, cvs_dir );
          if( debug ) display( ":: Directory '", cvs_dir, "' added to test list" );
        }
      }
    }
  }
}

# test for servers which return 200/403/401 for everything
req = http_get( item:"/non-existent" + rand() + "/", port:port );
res = http_keepalive_send_recv( port:port, data:req );
currReqs++;
if( ! res )
  failedReqs++;

if( res =~ "^HTTP/1\.[01] 200" ) {

  fake404 = 0;

  if( debug ) display( ":: This server returns 200 for non-existent directories" );

  foreach errmsg( errmessages_404 ) {
    if( egrep( pattern:errmsg, string:res, icase:TRUE ) && ! fake404 ) {
      fake404 = errmsg;
      if( debug ) display( ":: Using '", fake404, "' as an indication of a 404 error" );
      break;
    }
  }

  if( ! fake404 ) {
    if( debug ) display( ":: Could not find an error string to match against for the fake 404 response" );
    if( debug ) display( ":: Checks which rely on 200 responses are being disabled" );
    Check200 = FALSE;
  }
} else {
  fake404 = string( "BadString0987654321*DDI*" );
}

if( res =~ "^HTTP/1\.[01] 401" ) {
  if( debug ) display( ":: This server requires authentication for non-existent directories, disabling 401 checks" );
  Check401 = FALSE;
}

if( res =~ "^HTTP/1\.[01] 403" ) {
  if( debug ) display( ":: This server returns a 403 for non-existent directories, disabling 403 checks" );
  Check403 = FALSE;
}

if( res =~ "^HTTP/1\.[01] 30[0-8]" ) {
  if( debug ) display( ":: This server returns a redirect for non-existent directories, disabling redirect checks" );
  CheckRedirect = FALSE;
}

# start the actual directory scan
ScanRootDir = "/";

start = unixtime();
if( debug ) display( ":: Starting the directory scan..." );

# We make the list unique at the end to avoid having doubled
# entries from e.g. the robots.txt and for easier maintenance
# of the initial list which could contain multiple entries.
testDirList = make_list_unique( testDirList );

foreach cdir( testDirList ) {

  url = ScanRootDir + cdir;
  res = http_get_cache( item:url + "/", port:port );
  currReqs++;
  if( ! res ) {
    failedReqs++;
    if( failedReqs >= maxFailedReqs ) {
      if( debug ) display( ":: Max number of failed requests (" + maxFailedReqs + ") reached (Amount of requests done: " + currReqs + ") + exiting..." );
      exit( 0 );
    }
    continue;
  }

  if( cgi_dirs_exclude_servermanual ) {

    # Ignore Apache2 manual if it exists. This is just huge static content
    # and slows down the scanning without any real benefit.
    if( url =~ "^/manual" ) {
      man_res = http_get_cache( item:"/manual/en/index.html", port:port );
      currReqs++;
      if( man_res && "Documentation - Apache HTTP Server" >< man_res ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/servermanual_directories", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) + ", Content: Apache HTTP Server Manual" );
        continue;
      }
    }

    # Similar to the above for Tomcat
    if( url =~ "^/tomcat-docs" ) {
      man_res = http_get_cache( item:"/tomcat-docs/", port:port );
      currReqs++;
      if( man_res && "Apache Tomcat" >< man_res && "Documentation Index" >< man_res ) {
        set_kb_item( name:"www/" + host + "/" + port + "/content/servermanual_directories", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) + ", Content: Apache Tomcat Documentation" );
        continue;
      }
    }
  }

  http_code = int( substr( res, 9, 11 ) );
  if( ! res )
    res = "BogusBogusBogus";

  if( Check200 && http_code == 200 && ! ( egrep( pattern:fake404, string:res, icase:TRUE ) ) ) {

    if( debug ) display( ":: Discovered: " , ScanRootDir, cdir );

    add_discovered_list( dir:ScanRootDir + cdir, port:port, host:host );
  }

  # Pass any redirects we're getting to webmirror.nasl for further processing
  if( CheckRedirect && http_code =~ "^30[0-8]$" ) {

    if( debug )
      display( ":: Got a '", http_code, "' redirect for ", ScanRootDir, cdir, ", trying to extract the location..." );

    redirect = http_extract_location_from_redirect( port:port, data:res, debug:debug, current_dir:cdir );

    if( redirect ) {
      if( debug ) display( ":: Passing extracted redirect ", redirect ," to webmirror.nasl..." );
      set_kb_item( name:"DDI_Directory_Scanner/" + port + "/received_redirects", value:redirect );
      set_kb_item( name:"DDI_Directory_Scanner/" + host + "/" + port + "/received_redirects", value:redirect );
    }
  }

  if( Check403 && http_code == 403 ) {

    if( debug ) display( ":: Got a 403 for ", ScanRootDir, cdir, ", checking for file in the directory..." );

    req = http_get( item:ScanRootDir + cdir + "/NonExistent.html", port:port );
    res = http_keepalive_send_recv( data:req, port:port, bodyonly:FALSE );
    currReqs++;
    if( ! res )
      failedReqs++;

    if( res =~ "^HTTP/1\.[01] 403" ) {
      # the whole directory appears to be protected
      if( debug ) display( ":: 403 applies to the entire directory" );
    } else {
      if( debug ) display( ":: 403 applies to just directory indexes" );

      # the directory just has indexes turned off
      if( debug ) display( ":: Discovered: " , ScanRootDir, cdir );
      add_discovered_list( dir:ScanRootDir + cdir, port:port, host:host );
    }
  }

  if( Check401 && http_code == 401 ) {

    if( header = egrep( pattern:"^WWW-Authenticate\s*:", string:res, icase:TRUE ) ) {
      if( debug ) display( ":: Got a 401 for ", ScanRootDir + cdir, " containing a WWW-Authenticate header, adding to the dirs requiring auth..." );
      basic_auth = http_extract_basic_auth( data:res );
      add_auth_dir_list( dir:ScanRootDir + cdir, port:port, host:host, basic:basic_auth["basic_auth"], realm:basic_auth["realm"] );
    } else {
      if( debug ) display( ":: Got a 401 for ", ScanRootDir + cdir, " WITHOUT a WWW-Authenticate header, NOT adding to the dirs requiring auth..." );
    }
  }
}

if( debug ) display( ":: Finished scan (Done requests: ", currReqs, "), exiting..." );

exit( 0 );
