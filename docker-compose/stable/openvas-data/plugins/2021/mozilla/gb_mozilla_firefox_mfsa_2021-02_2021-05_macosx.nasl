# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817893");
  script_version("2021-03-09T09:52:25+0000");
  script_cve_id("CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23955", "CVE-2021-23956",
                "CVE-2021-23957", "CVE-2021-23958", "CVE-2021-23959", "CVE-2021-23960",
                "CVE-2021-23961", "CVE-2021-23962", "CVE-2021-23963", "CVE-2021-23964",
                "CVE-2021-23965");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-09 09:52:25 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-01-27 12:55:56 +0530 (Wed, 27 Jan 2021)");
  script_name("Mozilla Firefox Security Updates(mfsa_2021-02_2021-05)-Mac OS X");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Cross-origin information leakage via redirected PDF requests.

  - Type confusion when using logical assignment operators in JavaScript switch
    statements.

  - Clickjacking across tabs through misusing requestPointerLock.

  - File picker dialog could have been used to disclose a complete directory.

  - Screen sharing permission leaked across tabs.

  - Use-after-poison for incorrectly redeclared JavaScript variables during GC.

  - More internal network hosts could have been probed by a malicious webpage.

  - Use-after-poison in <code>nsTreeBodyFrame::RowCountChanged</code>.

  - Permission prompt inaccessible after asking for additional permissions.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service, disclose sensitive
  information and conduct clickjacking attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  85 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 85
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-03/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if(version_is_less(version:ffVer, test_version:"85"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"85", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
