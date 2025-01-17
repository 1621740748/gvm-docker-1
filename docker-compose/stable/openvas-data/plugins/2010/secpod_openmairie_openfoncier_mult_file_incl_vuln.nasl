##############################################################################
# OpenVAS Vulnerability Test
#
# openMairie openFoncier Multiple File Inclusion Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:openmairie:openfoncier";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902049");
  script_version("2021-08-04T02:26:48+0000");
  script_tag(name:"last_modification", value:"2021-08-04 02:26:48 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1945");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("openMairie openFoncier Multiple File Inclusion Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_openmairie_prdts_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openmairie/open_foncier/http/detected");

  script_tag(name:"insight", value:"Input passed to the parameter 'path_om' in various files and to
  the parameter 'dsn[phptype]' in 'scr/soustab.php' are not properly verified before being used to
  include files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"openMairie openFoncier is prone to multiple file inclusion
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include
  remote scripts and execute arbitrary commands with the privileges of the web server.");

  script_tag(name:"affected", value:"OpenMairie openFoncier version 2.00 and prior.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39607");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12366");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/scr/soustab.php?dsn[phptype]=../../../../../../../../vt-rfi.txt";

req = http_get(port: port, item: url);
res = http_send_recv(port: port, data: req);

if ("/vt-rfi.txt/" >< res && "failed to open stream" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
