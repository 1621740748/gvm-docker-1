###############################################################################
# OpenVAS Vulnerability Test
#
# Comersus Cart Cross-Site Scripting Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# From: "Thomas Ryan" <tommy@providesecurity.com>
# Date: 7.7.2004 18:10
# Subject: Comersus Cart Cross-Site Scripting Vulnerability

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12640");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0681", "CVE-2004-0682");
  script_bugtraq_id(10674);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Comersus Cart Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to version 5.098 or newer");

  script_tag(name:"summary", value:"The malicious user is able to compromise the parameters to invoke a
  Cross-Site Scripting attack. This can be used to take advantage of the trust between a client and
  server allowing the malicious user to execute malicious JavaScript on the client's machine or perform
  a denial of service shutting down IIS.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))exit(0);
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/comersus/store", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = http_get(item:string(dir, "/comersus_message.asp?message=vttest<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( isnull( r ) ) continue;

  if(r =~ "^HTTP/1\.[01] 200" && '<font size="2">vttest<script>foo</script>' >< r ) {
    security_message(port);
    exit(0);
  }
}

exit(99);
