###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Mysql Security Updates (jan2012-366304) 01 - Linux
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812343");
  script_version("2021-02-10T08:19:07+0000");
  script_cve_id("CVE-2012-0485", "CVE-2012-0120", "CVE-2012-0118", "CVE-2012-0119",
                "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0112", "CVE-2012-0113",
                "CVE-2012-0492", "CVE-2011-2262");
  script_bugtraq_id(51513, 51517, 51511, 51512, 51504, 51508, 51519, 51488, 51516, 51493);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-02-10 08:19:07 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-12-14 14:27:16 +0530 (Thu, 14 Dec 2017)");
  script_name("Oracle Mysql Security Updates (jan2012-366304) 01 - Linux");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in MySQL Server.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote users to affect integrity, availability
  and confidentiality.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.1.x, 5.5.x
  on Linux");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:oracle:mysql";

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"5.1", test_version2:"5.1.60") ||
   version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.19"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
  security_message(port:port, data: report);
  exit(0);
}

exit(99);