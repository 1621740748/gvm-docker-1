# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107305");
  script_version("2021-08-05T11:02:05+0000");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2018-04-20 16:04:01 +0200 (Fri, 20 Apr 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("Sensitive File Disclosure (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "drupal_detect.nasl", "sw_magento_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify files containing sensitive data at the remote
  web server like e.g.:

  - software (Blog, CMS) configuration or log files

  - web / application server configuration / password files (.htaccess, .htpasswd, web.config, web.xml, ...)

  - database backup files

  - SSH or SSL/TLS Private-Keys");

  script_tag(name:"vuldetect", value:"Enumerate the remote web server and check if sensitive files are accessible.");

  script_tag(name:"impact", value:"Based on the information provided in this files an attacker might
  be able to gather additional info and/or sensitive data like usernames and passwords.");

  script_tag(name:"solution", value:"The sensitive files shouldn't be accessible via a web server.
  Restrict access to it or remove it completely.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_timeout(900);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

# nb: We can't save an array within an array so we're using:
# array index = the file to check
# array value = the description and the regex of the checked file separated with #-#. Optional a third entry separated by #-# containing an "extra_check" for http_vuln_check()
genericfiles = make_array(
"/local.properties", "Generic properties file present that may contain sensitive configuration information.#-#^(#Properties File|perfmon\.installDir|apple\.awt\.graphics\.Use(OpenGL|UseQuartz)\s*=)",
"/.git-credentials", 'Git Credential Storage File containing a username and/or password.#-#^[ ]*https?://[^:@]+[:@]',
"/.idea/WebServers.xml", 'IntelliJ Platform Configuration File containing a username and/or password.#-#<component name="WebServers">#-#(password|username)=',
"/config/databases.yml", 'Symfony Framework Database Configuration File containing a username and/or password.#-#(param|class) ?:#-#(username|password) ?:',
"/app/config/config.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",
"/app/config/config_dev.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",
"/app/config/config_prod.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",
"/app/config/config_test.yml", "Symfony Framework Configuration File.#-#(^\s*(parameters|doctrine|database|framework)\s*:|https?://(www\.)?symfony\.com/doc)#-#(^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:|application-related-configuration)",
# See https://symfony.com/doc/current/logging.html, e.g.:
# [2020-05-06 19:14:00] request.ERROR: Uncaught PHP Exception Symfony\Component\HttpKernel\Exception\NotFoundHttpException:
# [2017-04-21 17:50:02] event.DEBUG: Notified event "console.command" to listener
"/app/logs/prod.log", "Symfony Framework log file.#-#^\[[^]]+\]\s+[^.]+\.(ERROR|NOTICE|INFO|DEBUG):\s+",
"/app/logs/dev.log", "Symfony Framework log file.#-#^\[[^]]+\]\s+[^.]+\.(ERROR|NOTICE|INFO|DEBUG):\s+",
"/config/database.yml", 'Rails Database Configuration File containing a username and/or password.#-#(adapter|database|production)\\s*:#-#(username|password)\\s*:',
"/DEADJOE", 'Editor JOE created the file DEADJOE on crash, which contains content of the currently edited files.#-#JOE (when it|was) aborted',
"/server.key", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/privatekey.key", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/myserver.key", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/key.pem", 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY',
"/id_rsa", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_dsa", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (DSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_dss", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (DSS|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_ecdsa", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/id_ed25519", 'SSH Private-Key publicly accessible.#-#^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----',
"/.env", 'Laravel ".env" file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_staging", 'Laravel ".env" file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_local", 'Laravel ".env" file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_production", 'Laravel ".env" file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_hosted", 'Laravel ".env" file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.env_baremetal", 'Laravel ".env" file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.local", 'Laravel config file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.production", 'Laravel config file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/.remote", 'Laravel config file present that may contain database credentials.#-#(APP_ENV|DB_DATABASE|DB_USERNAME|DB_PASSWORD)=',
"/app/config/parameters.yml", "Contao CMS, PrestaShop or Symfony Framework Database Configuration File containing a username and/or password.#-#(^\s*parameters\s*:|This file is auto-generated during the composer install)#-#^\s*((database_)?(user|password|host|name)|secret|dbhost|dbname)\s*:",
"/config.development.json", 'Ghost Database Configuration File containing a username and/or password.#-#"database" ?:#-#"(user|password)"',
"/config.production.json", 'Ghost Database Configuration File containing a username and/or password.#-#"database" ?:#-#"(user|password)"',
# https://docs.djangoproject.com/en/2.0/ref/settings/
"/settings.py", "Django Configuration File containing a SECRET_KEY or a username and/or password.#-#(SECRET_KEY ?=|'USER' ?:|'PASSWORD' ?:)",
# https://blog.dewhurstsecurity.com/2018/06/07/database-sql-backup-files-alexa-top-1-million.html
# https://github.com/hannob/snallygaster/blob/a423d4063f37763f9288505c0baca69e216daa7c/snallygaster#L352-L355
"/dump.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/database.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/1.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/backup.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/data.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/db_backup.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/dbdump.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/db.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/localhost.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/mysql.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/site.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/sql.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/temp.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/users.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/translate.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
"/mysqldump.sql", 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )',
# e.g.
# {"php":"7.2.4-1+ubuntu16.04.1+deb.sury.org+1","version":"2.11.1:v2.11.1#ad94441c17b8ef096e517acccdbf3238af8a2da8","rules":{"binary_operator_spaces":true,"blank_line_after_opening_tag":true,"blank_line_before_statement":{"statements":
# {"php":"5.6.26-1+deb.sury.org~xenial+1","version":"2.0.0","rules":{"array_syntax":{"syntax":"short"},"combine_consecutive_unsets":true,"general_phpdoc_annotation_remove":
"/.php_cs.cache", 'Cache file .php_cs.cache of PHP-CS-Fixer could expose a listing of PHP files.#-#^\\{"php":"#-#"(version|rules|binary_operator_spaces|blank_line_after_opening_tag|blank_line_before_statement|array_syntax|syntax|statements)":"',
# Example: https://github.com/Flexberry/javascript-project-template/blob/master/.coveralls.yml.example
"/.coveralls.yml", "Coveralls Configuration File containing a secret repo token for a repository accessible.#-#^repo_token\s*:.+",
# Example syntax:
# https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
# https://wiki.selfhtml.org/wiki/Webserver/htaccess/Passwortschutz
# https://httpd.apache.org/docs/2.4/howto/auth.html
"/.htpasswd", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.htpasswd-users", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.htpasswd-all", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.htpasswds", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.htuser", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.htusers", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.access", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.passwd", "Apache HTTP Server password file for Basic Authentication accessible.#-#^[^:]+:(\$2[abxy]?\$[0-9]{2}\$[0-9a-zA-Z/.]{53}|\$apr1\$[0-9a-zA-Z/.]{8}\$[0-9a-zA-Z/.]{22}|\{SHA\}[0-9a-zA-Z/.=+]{28}|\{SSHA\}[0-9a-zA-Z/.=+]{40}|[0-9a-zA-Z/.]{13})$",
"/.htaccess", "Apache HTTP Server .htaccess file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*(<Directory [^>]+>|</Directory>|</?RequireAll>|Require (group |user |valid-user|ldap-group |all |not host |not ip)|GroupName: |Auth(Type|Name|BasicProvider|LDAPURL|(User|Group|DBMUser)File) )",
# https://docs.microsoft.com/en-us/iis-administration/security/integrated/web.config
# https://docs.microsoft.com/en-us/troubleshoot/aspnet/create-web-config
"/web.config", "Microsoft IIS / ASP.NET Core Module web.config file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*<(configuration|system\.web(Server)?)>#-#^\s*</(configuration|system\.web(Server)?)>",
"/WEB-INF/web.xml", "Configuration file of various application servers (Apache Tomcat, Mortbay Jetty, ...) accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*<(web-app( .+|>$)|servlet>$)#-#^\s*</(web-app|servlet)>$",
"/web.xml", "Configuration file of various application servers (Apache Tomcat, Mortbay Jetty, ...) accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*<(web-app( .+|>$)|servlet>$)#-#^\s*</(web-app|servlet)>$",
"/WEB-INF/webapp.properties", "Allaire JRUN configuration file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*\[?(file\.browsedirs=(false|true)|users\.location=.+)",
"/webapp.properties", "Allaire JRUN configuration file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*\[?(file\.browsedirs=(false|true)|users\.location=.+)",
"/WEB-INF/local.properties", "Allaire JRUN configuration file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*\[?(file\.browsedirs=(false|true)|users\.location=.+)",
"/local.properties", "Allaire JRUN configuration file accessible. This could contain sensitive information about the structure of the application / web server and shouldn't be accessible.#-#^\s*\[?(file\.browsedirs=(false|true)|users\.location=.+)",
"/service.cnf", "Microsoft IIS / SharePoint / FrontPage configuration file#-#^vti_[^:]+:[A-Z]{2}\|.+",
# https://linux.die.net/man/5/esmtprc
"/.esmtprc", "esmtp configuration file containing a username and password#-#^\s*username\s*=.+#-#^\s*password\s*=.+",
# https://framework.zend.com/manual/1.12/en/zend.application.quick-start.html
# https://framework.zend.com/manual/1.12/en/zend.application.available-resources.html
# https://github.com/feibeck/application.ini/blob/master/application.ini
"/application/configs/application.ini", "Zend Framework configuration file#-#^\s*;?\s*(phpSettings|pluginpaths|resources\.(db|cachemanager|dojo|frontController|layout|locale|log|mail|modules|navigation|session|view|jQuery)|bootstrap)\.[^=]+=.+#-#^\s*\[.*production\]",
"/configs/application.ini", "Zend Framework configuration file#-#^\s*;?\s*(phpSettings|pluginpaths|resources\.(db|cachemanager|dojo|frontController|layout|locale|log|mail|modules|navigation|session|view|jQuery)|bootstrap)\.[^=]+=.+#-#^\s*\[.*production\]",
# https://blog.robomongo.org/robo-3t-1-3/ has some examples
"/robomongo.json", 'RoboMongo / Robo 3T configuration file that may contain sensitive configuration information.#-#^\\s*"(userName|userPassword(Encrypted)?|databaseName|serverHost)"\\s*:\\s*"[^"]+"',
"/robo3T.json", 'RoboMongo / Robo 3T configuration file that may contain sensitive configuration information.#-#^\\s*"(userName|userPassword(Encrypted)?|databaseName|serverHost)"\\s*:\\s*"[^"]+"',
"/robo3t.json", 'RoboMongo / Robo 3T configuration file that may contain sensitive configuration information.#-#^\\s*"(userName|userPassword(Encrypted)?|databaseName|serverHost)"\\s*:\\s*"[^"]+"',
# https://airflow.apache.org/docs/apache-airflow/stable/howto/set-config.html
"/airflow.cfg", "Apache Airflow file that may contain sensitive configuration information.#-#^\s*\[core\]#-#^\s*\[(api|celery|atlas|smtp|webserver)\]",
# https://book.cakephp.org/phinx/0/en/configuration.html
"/phinx.yml", "Phinx configuration file containing database configuration info.#-#^\\s*environments:#-#^\\s*(host|name|user|pass):.+",
"/phinx.yaml", "Phinx configuration file containing database configuration info.#-#^\\s*environments:#-#^\\s*(host|name|user|pass):.+",
"/phinx.json", 'Phinx configuration file containing database configuration info.#-#^\\s*"environments":#-#^\\s*"(host|name|user|pass)":.+',
# https://github.com/dodiksunaryo/qdpm/blob/master/core/config/databases.yml.sample
"/core/config/databases.yml", "qdPM configuration file containing database configuration info.#-#^\s*dsn:.+#-#^\s(username|password):.+",
"/databases.yml", "qdPM configuration file containing database configuration info.#-#^\s*dsn:.+#-#^\s(username|password):.+"
);

# https://doc.nette.org/en/configuring or https://github.com/nette/examples/blob/master/CD-collection/app/config.neon
foreach nettedir( make_list( "/app/config", "/app", "" ) ) {
  genericfiles[nettedir + "/config.neon"] = "Nette Framework config file is publicly accessible.#-#^((php|application|database|services|security|latte|session|extensions):|# SECURITY WARNING: it is CRITICAL)#-#^ *((date\.timezone|mapping|dsn|debugger|users|roles|resources|errorPresenter|catchExceptions|silentLinks|user|password|macros):|- App)";
}

# Add domain specific key names and backup files from above
hnlist = create_hostname_parts_list();
foreach hn( hnlist ) {
  genericfiles["/" + hn + ".key"] = 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY';
  genericfiles["/" + hn + ".pem"] = 'SSL/TLS Private-Key is publicly accessible.#-#BEGIN (RSA|DSA|DSS|EC)? ?PRIVATE KEY';
  genericfiles["/" + hn + ".sql"] = 'Database backup file publicly accessible.#-#^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )';
}

magentofiles = make_array(
"/app/etc/local.xml", 'Magento 1 Database Configuration File containing a username and/or password.#-#(<config|Mage)#-#<(username|password)>' );

drupalfiles = make_array(
"/sites/default/private/files/backup_migrate/scheduled/test.txt", 'If the file "test.txt" is accessible on a Drupal server, it means that site backups may be publicly exposed.#-#this file should not be publicly accessible',
"/sites/default/files/.ht.sqlite", "Drupal Database file publicly accessible.#-#^SQLite format [0-9]" );

global_var report, VULN;

function check_files( filesarray, dirlist, port ) {

  local_var filesarray, dirlist, port;
  local_var dir, file, infos, desc, pattern, extra, url;

  foreach dir( dirlist ) {

    if( dir == "/" )
      dir = "";

    foreach file( keys( filesarray ) ) {

      # infos[0] contains the description, infos[1] the regex. Optionally infos[2] contains an extra_check for http_vuln_check.
      infos = split( filesarray[file], sep:"#-#", keep:FALSE );
      if( max_index( infos ) < 2 )
        continue; # Something is wrong with the provided info...

      desc = infos[0];
      pattern = infos[1];

      if( max_index( infos ) > 2 )
        extra = make_list( infos[2] );
      else
        extra = NULL;

      url = dir + file;

      if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:pattern, extra_check:extra, usecache:TRUE ) ) {
        report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + ":" + desc;
        VULN = TRUE;
      }
    }
  }
}

report = 'The following files containing sensitive information were identified (URL:Description):\n';

port = http_get_port( default:80 );

dirlist = make_list_unique( "/", http_cgi_dirs( port:port ) );
check_files( filesarray:genericfiles, dirlist:dirlist, port:port );

drdirs = get_app_location( port:port, cpe:"cpe:/a:drupal:drupal", nofork:TRUE );
if( drdirs )
  drupaldirlist = make_list_unique( drdirs, dirlist );
else
  drupaldirlist = dirlist;
check_files( filesarray:drupalfiles, dirlist:drupaldirlist, port:port );

madirs = get_app_location( port:port, cpe:"cpe:/a:magentocommerce:magento", nofork:TRUE );
if( madirs )
  magentodirlist = make_list_unique( madirs, dirlist );
else
  magentodirlist = dirlist;
check_files( filesarray:magentofiles, dirlist:magentodirlist, port:port );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
