###############################################################################
# OpenVAS Vulnerability Test
#
# Ultimate PHP Board multiple XSS vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat dot cc>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.19499");
  script_version("2021-05-17T09:15:04+0000");
  script_tag(name:"last_modification", value:"2021-05-17 09:15:04 +0000 (Mon, 17 May 2021)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_bugtraq_id(14348, 14350);
  script_xref(name:"OSVDB", value:"18143");
  script_xref(name:"OSVDB", value:"18144");
  script_xref(name:"OSVDB", value:"18145");
  script_xref(name:"OSVDB", value:"18146");
  script_xref(name:"OSVDB", value:"18147");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ultimate PHP Board multiple XSS vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.retrogod.altervista.org/upbgold196xssurlspoc.txt");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/402461");
  script_xref(name:"URL", value:"http://www.retrogod.altervista.org/upbgold196poc.php.txt");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote version of Ultimate PHP Board (UPB) is affected by several
  cross-site scripting vulnerabilities. This issue is due to a failure of the application to properly
  sanitize user-supplied input.");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("url_func.inc");
include("misc_func.inc");

vtstrings = get_vt_strings();
xss = "<script>alert(" + vtstrings["lowercase_rand"] + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode( str:xss );

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/chat/send.php?css=", exss );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && xss >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
