###############################################################################
# OpenVAS Vulnerability Test
#
# Invision Power Top Site List SQL Injection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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

# From: JeiAr [security@gulftech.org]
# Subject: Invision Power Top Site List SQL Inection
# Date: Monday 15/12/2003 23:38

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11956");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9229);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Invision Power Top Site List SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version of this CGI suite");

  script_tag(name:"summary", value:"The remote host is running 'Invision Power Top Site List', a site ranking
  script written in PHP.

  There is a SQL injection vulnerability in this CGI suite, due to a lack of user-input sanitizing, which
  may allow an attacker to execute arbitrary SQL commands on this host, and therefore gain the control of
  the database of this site.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php?offset=[%20Problem%20Here%20]";

  if( http_vuln_check( port:port, url:url, pattern:"syntax to use near '\[ Problem Here \]" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
