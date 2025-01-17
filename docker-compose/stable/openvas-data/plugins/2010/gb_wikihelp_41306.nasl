###############################################################################
# OpenVAS Vulnerability Test
#
# Wiki Web Help Cross Site Scripting and HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100700");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
  script_bugtraq_id(41306);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Wiki Web Help Cross Site Scripting and HTML Injection Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Wiki Web Help is prone to a cross-site scripting vulnerability and
  multiple HTML-injection vulnerabilities because it fails to properly
  sanitize user-supplied input before using it in dynamically
  generated content.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code could run in the context of the
  affected browser, potentially allowing the attacker to steal cookie-
  based authentication credentials or to control how the site is
  rendered to the user. Other attacks are also possible.");

  script_tag(name:"affected", value:"Wiki Web Help 0.2.7 is vulnerable, other versions may also be
  affected.");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41306");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/?func=detail&atid=1296085&aid=3025530&group_id=307693");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( !http_can_host_php( port:port ) )
  exit( 0 );

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/wwh", "/wikihelp", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/revert.php?rev=%3Cscript%3Ealert(%27", vt_strings["lowercase"], "%27)%3C/script%3E" );

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('" + vt_strings["lowercase"] + "'\)</script>", check_header: TRUE, extra_check:"Revert to revision" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
