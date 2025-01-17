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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817844");
  script_version("2021-01-15T07:53:46+0000");
  script_cve_id("CVE-2020-26951", "CVE-2020-16012", "CVE-2020-26953", "CVE-2020-26956",
                "CVE-2020-26958", "CVE-2020-26959", "CVE-2020-26960", "CVE-2020-26968",
                "CVE-2020-26961", "CVE-2020-26965");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-01-15 07:53:46 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2020-11-18 15:50:09 +0530 (Wed, 18 Nov 2020)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2020-50_2020-52)-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A parsing and event loading mismatch in Thunderbird's SVG code.

  - A variable time processing of cross-origin images during drawImage calls in
    Skia library.

  - Fullscreen could be enabled without displaying the security UI.

  - An improper sanitization in manual and clipboard API.

  - Thunderbird did not block execution of scripts with incorrect MIME types.

  - An use-after-free error in WebRequestService and in uses of nsTArray.

  - DoH did not filter IPv4 mapped IP Addresses.

  - Software keyboards may have remembered typed passwords.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass security, disclose sensitive information and
  run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  78.5 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 78.5
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-52/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"78.5"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"78.5", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
