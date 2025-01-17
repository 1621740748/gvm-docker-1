###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe ColdFusion Remote Code Execution And Information Disclosure Vulnerabilities
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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811696");
  script_version("2021-03-24T09:05:19+0000");
  script_cve_id("CVE-2017-11286", "CVE-2017-11285", "CVE-2017-11283", "CVE-2017-11284");
  script_bugtraq_id(100715, 100711, 100708);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-24 09:05:19 +0000 (Wed, 24 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-09-14 15:04:23 +0530 (Thu, 14 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Remote Code Execution And Information Disclosure Vulnerabilities (APSB17-30)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to information disclosure and
  remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper Restriction of XML External Entity Reference.

  - Improper Neutralization of Input During Web Page Generation.

  - Deserialization of Untrusted Data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application
  and gain access to sensitive information.");

  script_tag(name:"affected", value:"ColdFusion 11 before Update 13 and ColdFusion
  2016 before update 5.");

  script_tag(name:"solution", value:"Upgrade to ColdFusion 11 Update 13 or 2016
  update 5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb17-30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("adobe/coldfusion/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+")) # nb: The HTTP Detection VT might only extract the major version like 11 or 2021
  exit(0);

version = infos["version"];
location = infos["location"];

#https://helpx.adobe.com/coldfusion/kb/coldfusion-11-update-13.html
if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.13.303667")) {
  fix = "11.0.13.303668";
}

#https://helpx.adobe.com/coldfusion/kb/coldfusion-2016-update-5.html
else if(version_in_range(version:version, test_version:"2016.0", test_version2:"2016.0.05.303688")) {
  fix = "2016.0.05.303689";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);