###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix Web Interface XSS
#
# Authors:
# Michael J. Richardson <michael.richardson@protiviti.com>
#
# Copyright:
# Copyright (C) 2003 Michael J. Richardson
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
  script_oid("1.3.6.1.4.1.25623.1.0.12301");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1157");
  script_bugtraq_id(8939);
  script_xref(name:"OSVDB", value:"2762");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Citrix Web Interface XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Michael J. Richardson");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to Citrix Web Interface 2.1 or newer.");
  script_tag(name:"summary", value:"The remote server is running a Citrix Web Interface server that is vulnerable to cross site scripting.");
  script_tag(name:"impact", value:"When a user fails to authenticate, the Citrix Web Interface includes the error message text in the URL.
  The error message can be tampered with to perform an XSS attack.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list( "/citrix/nfuse/default", "/citrix/MetaframeXP/default" ) ) {

  url = dir + "/login.asp?NFuse_LogoutId=&NFuse_MessageType=Error&NFuse_Message=<SCRIPT>alert('Ritchie')</SCRIPT>&ClientDetection=ON";

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<SCRIPT>alert\('Ritchie'\)</SCRIPT>" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
