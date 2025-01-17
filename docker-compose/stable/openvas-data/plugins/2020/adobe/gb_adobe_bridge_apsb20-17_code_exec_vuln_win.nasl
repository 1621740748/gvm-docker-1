# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:bridge_cc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816817");
  script_version("2021-07-08T02:00:55+0000");
  script_cve_id("CVE-2020-9551", "CVE-2020-9552");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-08 02:00:55 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-27 19:57:00 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-19 14:42:29 +0000 (Thu, 19 Mar 2020)");
  script_name("Adobe Bridge Security Updates (apsb20-17)-Windows");

  script_tag(name:"summary", value:"The host is installed with Adobe Bridge
  and is prone to multiple RCE vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an out of
  bounds write and heap-based buffer overflow errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Bridge prior to 10.0.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Bridge 10.0.3 or later. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb20-17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

## 10.0.3 == 10.0.3.138
if(version_is_less(version:vers, test_version:"10.0.3.138"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.0.3 (10.0.3.138)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
