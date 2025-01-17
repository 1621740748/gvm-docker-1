###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java System Web Proxy Server Two Vulnerabilities (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800026");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4541");
  script_bugtraq_id(31691);
  script_name("Sun Java System Web Proxy Server Two Vulnerabilities (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32227");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45782");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2781");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-242986-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("Sun-Java-System-Web-Proxy-Server/banner", "login/SSH/success");
  script_dependencies("gather-package-list.nasl", "gb_get_http_banner.nasl");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code in the context
  of the server, and failed attacks may cause denial-of-service condition.");

  script_tag(name:"affected", value:"Sun Java System Web Proxy Server versions prior to 4.0.8 on all running platform.");

  script_tag(name:"insight", value:"The flaw exists due to a boundary error in the FTP subsystem and in processing
  HTTP headers. This issue resides within the code responsible for handling HTTP GET requests.");

  script_tag(name:"summary", value:"This host has Sun Java Web Proxy Server running, which is prone
  to heap buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Update to version 4.0.8 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("ssh_func.inc");
include("version_func.inc");

sunPorts = http_get_ports(default_port_list:make_list(8081));
foreach sunPort(sunPorts) {

  banner = http_get_remote_headers(port:sunPort);
  if(!banner)
    continue;

  if(banner =~ "Server: Sun-Java-System-Web-Proxy-Server/[0-3]\.0")
    security_message(port:sunPort);

  if(banner =~ "Server: Sun-Java-System-Web-Proxy-Server/4\.0")
    check_ssh = TRUE;
}

if(check_ssh) {

  sock = ssh_login_or_reuse_connection();
  if(!sock)
    exit(0);

  sunName = ssh_find_file(file_name:"/proxy-admserv/start$", useregex:TRUE, sock:sock);
  foreach binary_sunName (sunName)
  {
    binary_name = chomp(binary_sunName);
    if(!binary_name)
      continue;

    sunVer = ssh_get_bin_version(full_prog_name:binary_name, version_argv:"-version", sock:sock, ver_pattern:"Web Proxy Server ([0-9.]+)");
    if(sunVer)
    { # Grep for versions prior to 4.0.8
      if(version_in_range(version:sunVer[1], test_version:"4.0", test_version2:"4.0.7")){
        security_message(sunPort);
      }
      ssh_close_connection();
      exit(0);
    }
  }
 ssh_close_connection();
}
