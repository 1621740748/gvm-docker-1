###############################################################################
# OpenVAS Vulnerability Test
#
# Moodle Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800766");
  script_version("2020-12-08T08:52:45+0000");
  script_tag(name:"last_modification", value:"2020-12-08 08:52:45 +0000 (Tue, 08 Dec 2020)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1614", "CVE-2010-1615", "CVE-2010-1617", "CVE-2010-1618", "CVE-2010-1619");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Moodle Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://moodle.org/security/");
  script_xref(name:"URL", value:"http://tracker.moodle.org/browse/MDL-17207");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"affected", value:"Moodle version 1.8.x prior to 1.8.12, 1.9.x prior to 1.9.8.");

  script_tag(name:"insight", value:"- Input data passed to add_to_log()function in wiki module in
  'mod/wiki/view.php' and 'lib/form/selectgroups.php' is not properly sanitised before being used in SQL query

  - Error in 'user/view.php', which fails to check role

  - Error in 'phpCAS client library', allows remote attackers to inject
  arbitrary web script or HTML via a crafted URL

  - Error in 'fix_non_standard_entities' function in the
  'KSES HTML text cleaning library', allows remote attackers to inject
  arbitrary web script or HTML via crafted HTML entities");

  script_tag(name:"solution", value:"Update to version 1.8.12, 1.9.8 or later.");

  script_tag(name:"summary", value:"This host is running Moodle and is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary web
  script or HTML via a crafted URL.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.8", test_version2:"1.8.11") ||
   version_in_range(version:version, test_version:"1.9", test_version2:"1.9.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.8.12 / 1.9.8", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
