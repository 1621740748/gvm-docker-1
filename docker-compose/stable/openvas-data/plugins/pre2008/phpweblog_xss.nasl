###############################################################################
# OpenVAS Vulnerability Test
#
# phpWebLog Cross Site Scripting
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# Filip Groszynski <groszynskif@gmail.com>
# 2005-03-07 21:21
# phpWebLog <= 0.5.3 arbitrary file inclusion (VXSfx)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17343");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-0698");
  script_bugtraq_id(12747);
  script_name("phpWebLog Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5GP0C1PF5W.html");

  script_tag(name:"solution", value:"Disable this script.");

  script_tag(name:"summary", value:"The remote web server is running phpWebLog, a news and content management
  system written in PHP that is prone to several flaws, including possibly arbitrary code execution.");

  script_tag(name:"impact", value:"Due to improper filtering done by 'search.php' a remote attacker can
  cause the phpWebLog product to include arbitrary HTML and/or JavaScript. An attacker may use this bug
  to perform a cross site scripting attack using the remote host.  There are also reportedly two flaws
  that, if PHP's 'register_globals' setting is enabled, allow for local file disclosure and arbitrary
  code execution.");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/search.php?query=we+%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E&topic=0&limit=30";

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document.cookie\)</script>" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
