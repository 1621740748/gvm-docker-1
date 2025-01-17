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
  script_oid("1.3.6.1.4.1.25623.1.0.817525");
  script_version("2020-12-14T08:58:12+0000");
  script_cve_id("CVE-2020-26950");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-14 08:58:12 +0000 (Mon, 14 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-11-10 14:51:11 +0530 (Tue, 10 Nov 2020)");
  script_name("Mozilla Firefox Security Updates(mfsa_2020-49_2020-49)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to 'Write' side effects
  in 'MCallGetProperty' opcode not accounted.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code on the system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  82.0.3 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 82.0.3
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-49/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"82.0.3"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"82.0.3", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
