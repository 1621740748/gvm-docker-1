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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817035");
  script_version("2021-06-23T12:24:40+0000");
  script_cve_id("CVE-2020-12399", "CVE-2020-12405", "CVE-2020-12406", "CVE-2020-12407",
                "CVE-2020-12408", "CVE-2020-12409", "CVE-2020-12410", "CVE-2020-12411");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-23 12:24:40 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"creation_date", value:"2020-06-03 13:30:51 +0530 (Wed, 03 Jun 2020)");
  script_name("Mozilla Firefox Security Update (mfsa_2020-20_2020-21) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Timing attack on DSA signatures in NSS library.

  - Use-after-free in SharedWorkerService.

  - JavaScript type confusion with NativeTypes.

  - WebRender leaking GPU memory when using border-image CSS directive.

  - URL spoofing when using IP addresses.

  - URL spoofing with unicode characters.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial-of-service or execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 77 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 77
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-20/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"77")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"77", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);