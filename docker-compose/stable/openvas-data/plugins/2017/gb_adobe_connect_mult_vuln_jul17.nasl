###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Connect Multiple Vulnerabilities Jul17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811480");
  script_version("2020-10-23T13:29:00+0000");
  script_cve_id("CVE-2017-3101", "CVE-2017-3102", "CVE-2017-3103");
  script_bugtraq_id(99521, 99517, 99518);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-07-13 12:18:52 +0530 (Thu, 13 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Multiple Vulnerabilities Jul17");

  script_tag(name:"summary", value:"The host is installed with Adobe Connect
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - User Interface (UI) Misrepresentation of Critical Information.

  - Improper Neutralization of Input During Web Page Generation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct reflected and stored cross-site scripting attacks, UI
  redressing (or clickjacking) attacks.");

  script_tag(name:"affected", value:"Adobe Connect versions before 9.6.2");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.6.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb17-22.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!acVer = get_app_version(cpe:CPE, port:acPort)){
  exit(0);
}

if(version_is_less(version:acVer, test_version:"9.6.2"))
{
  report = report_fixed_ver(installed_version:acVer, fixed_version:"9.6.2");
  security_message(data:report, port:acPort);
  exit(0);
}
