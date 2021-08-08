###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! SQL Injection And Cross Site Scripting Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812680");
  script_version("2021-06-15T02:00:29+0000");
  script_cve_id("CVE-2018-6376", "CVE-2018-6377");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-13 18:10:00 +0000 (Tue, 13 Feb 2018)");
  script_tag(name:"creation_date", value:"2018-01-31 11:32:03 +0530 (Wed, 31 Jan 2018)");

  script_name("Joomla! SQL Injection And Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Joomla and is prone to SQL injection and cross-site
scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Lack of type casting of a variable in SQL statement in the Hathor postinstall message.

  - Inadequate input filtering in com_fields in multiple field types, i.e. list, radio and checkbox.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow remote attackers to conduct SQL
injection and XSS attacks.");

  script_tag(name:"affected", value:"Joomla core version 3.7.0 through 3.8.3");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/720-20180103-core-xss-vulnerability.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/722-20180105-core-sqli-vulnerability.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:jPort, exit_no_version:TRUE )) exit(0);
jVer = infos['version'];
path = infos['location'];

if(jVer =~ "^(3\.)") {
  if(version_in_range(version:jVer, test_version:"3.7.0", test_version2:"3.8.3")) {
    report = report_fixed_ver(installed_version:jVer, fixed_version:"3.8.4", install_path:path);
    security_message(port:jPort, data:report);
    exit(0);
  }
}

exit(0);
