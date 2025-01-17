###############################################################################
# OpenVAS Vulnerability Test
#
# PIX Firewall Manager Directory Traversal
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.10819");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(691);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-1999-0158");
  script_name("PIX Firewall Manager Directory Traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8181);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"It is possible to read arbitrary files on the remote host
  through the remote web server.");

  script_tag(name:"impact", value:"This flaw can be used to bypass the
  management software's password protection and possibly retrieve the enable password for the Cisco PIX.");

  script_tag(name:"insight", value:"It is possible to read arbitrary files on this machine by using
  relative paths in the URL.

  This vulnerability has been assigned Cisco Bug ID: CSCdk39378.

  Note: Cisco originally recommended upgrading to version 4.1.6b or version 4.2, however the same
  vulnerability has been found in version 4.3.

  Cisco now recommends to disable the software completely and to migrate to the new PIX Device
  Manager software.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8181 );

url = "/..\\pixfir~1\\how_to_login.html";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( res && "How to login" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
