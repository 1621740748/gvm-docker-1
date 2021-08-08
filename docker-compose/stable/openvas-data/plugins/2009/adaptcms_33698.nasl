###############################################################################
# OpenVAS Vulnerability Test
#
# AdaptCMS Lite Cross Site Scripting and Remote File Include Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100373");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-12-02 19:43:26 +0100 (Wed, 02 Dec 2009)");
  script_bugtraq_id(33698);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0526");
  script_name("AdaptCMS Lite Cross Site Scripting and Remote File Include Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33698");
  script_xref(name:"URL", value:"http://www.adaptcms.com");

  script_tag(name:"summary", value:"AdaptCMS Lite is prone to multiple cross-site scripting
  vulnerabilities and a remote file-include vulnerability because it
  fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute malicious PHP code
  in the context of the webserver process. This may allow the attacker to compromise the application
  and the underlying system. The attacker may also execute script code in an unsuspecting user's
  browser or steal cookie-based authentication credentials. Other attacks are also possible.");

  script_tag(name:"affected", value:"AdaptCMS Lite 1.4 and 1.5 are vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/adaptcms", "/cms", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/sitemap.xml", port:port );
  if( ! buf )
    continue;

  if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"Generated by AdaptCMS", string:buf, icase:TRUE ) ) {

    url = string( dir, "/index.php?view=redirect&url=javascript:alert(%22vt-xss-test%22)" );

    if( http_vuln_check( port:port, url:url, pattern:'"vt-xss-test"', check_header:TRUE ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );