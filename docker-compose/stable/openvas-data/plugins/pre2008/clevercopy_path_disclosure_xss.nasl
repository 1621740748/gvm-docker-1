###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple vulnerabilities in Clever Copy
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
# Fixed by Tenable:
#   - added CVE and OSVDB xrefs.
#   - added See also.
#   - lowered Risk Factor from Medium.
#   - changed exploit from SQL injection to XSS, which is what these BIDs cover.
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
  script_oid("1.3.6.1.4.1.25623.1.0.19392");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2326");
  script_bugtraq_id(14278, 14395, 14397);
  script_xref(name:"OSVDB", value:"17919");
  script_xref(name:"OSVDB", value:"18349");
  script_xref(name:"OSVDB", value:"18350");
  script_xref(name:"OSVDB", value:"18351");
  script_xref(name:"OSVDB", value:"18352");
  script_xref(name:"OSVDB", value:"18353");
  script_xref(name:"OSVDB", value:"18354");
  script_xref(name:"OSVDB", value:"18355");
  script_xref(name:"OSVDB", value:"18356");
  script_xref(name:"OSVDB", value:"18357");
  script_xref(name:"OSVDB", value:"18358");
  script_xref(name:"OSVDB", value:"18359");
  script_xref(name:"OSVDB", value:"18360");
  script_xref(name:"OSVDB", value:"18361");
  script_xref(name:"OSVDB", value:"18509");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Multiple vulnerabilities in Clever Copy");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2005/07/clever-copy-calendarphp-yr-variable.html");
  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2005/07/clever-copy-path-disclosure-and-xss.html");
  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2005/07/clever-copy-unauthorized-read-delete.html");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote version of Clever Copy contains multiple vulnerabilities
  that can lead to path disclosure, cross-site scripting and unauthorized access to private messages");

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
xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/results.php?", 'searchtype=">', exss, "category&searchterm=", vtstrings["default"] );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && xss >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
