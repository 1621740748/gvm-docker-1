###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Multiple Unspecified vulnerabilities - 01 May14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804574");
  script_version("2021-02-10T08:19:07+0000");
  script_cve_id("CVE-2014-0384", "CVE-2014-2419", "CVE-2014-2438");
  script_bugtraq_id(66835, 66880, 66846);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-02-10 08:19:07 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"creation_date", value:"2014-05-08 12:56:56 +0530 (Thu, 08 May 2014)");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities - 01 May14 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is prone to multiple unspecified
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors related
  to Partition, Replication and XML subcomponent.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate certain data
  and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Oracle MySQL version 5.5.35 and earlier and 5.6.15 and earlier on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57940");
  script_xref(name:"URL", value:"http://www.scaprepo.com/view.jsp?id=oval:org.secpod.oval:def:701638");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

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

if(vers =~ "^5\.[56]") {
  if(version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.35")||
     version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.15")) {
    security_message(port:port);
    exit(0);
  }
}
