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
  script_oid("1.3.6.1.4.1.25623.1.0.817005");
  script_version("2020-10-23T13:29:00+0000");
  script_cve_id("CVE-2020-1239", "CVE-2020-1238", "CVE-2020-6831");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-05-06 18:10:22 +0530 (Wed, 06 May 2020)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2020-16_2020-18)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to a buffer
  overflow in SCTP chunk input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial-of-service or execute arbitrary code
  on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 68.8 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 68.8
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-18/");
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

if(version_is_less(version:tbVer, test_version:"68.8"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"68.8", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
