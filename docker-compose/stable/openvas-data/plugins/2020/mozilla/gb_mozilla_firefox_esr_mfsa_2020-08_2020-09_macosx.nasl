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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816703");
  script_version("2020-07-17T05:57:41+0000");
  script_cve_id("CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811",
                "CVE-2019-20503", "CVE-2020-6812", "CVE-2020-6814");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-17 05:57:41 +0000 (Fri, 17 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-03-12 10:44:08 +0530 (Thu, 12 Mar 2020)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2020-08_2020-09)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A use-after-free issue when removing data about origins.

  - A use-after-free in cubeb during stream destruction.

  - An out-of-bounds read issue.

  - Memory safety bugs.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary commands, gain access to sensitive information or cause denial
  of service condition.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 68.6
  on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 68.6
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-09/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

ffVer = infos["version"];
ffPath = infos["location"];

if(version_is_less(version:ffVer, test_version:"68.6")) {
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"68.6", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);
