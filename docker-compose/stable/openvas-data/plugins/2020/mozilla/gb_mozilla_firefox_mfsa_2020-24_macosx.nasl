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
  script_oid("1.3.6.1.4.1.25623.1.0.817211");
  script_version("2020-07-21T08:11:15+0000");
  script_cve_id("CVE-2020-12415", "CVE-2020-12416", "CVE-2020-12417", "CVE-2020-12418",
                "CVE-2020-12419", "CVE-2020-12420", "CVE-2020-12402", "CVE-2020-12421",
                "CVE-2020-12422", "CVE-2020-12423", "CVE-2020-12424", "CVE-2020-12425",
                "CVE-2020-12426");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-21 08:11:15 +0000 (Tue, 21 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 10:56:32 +0530 (Thu, 02 Jul 2020)");
  script_name("Mozilla Firefox Security Updates (MacOSX)-June 30 2020");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - AppCache manifest poisoning due to url encoded character processing.

  - Use-after-free in WebRTC VideoBroadcaster.

  - Memory corruption due to missing sign-extension for ValueTags on ARM64.

  - Information disclosure due to manipulated URL object.

  - Use-after-free in nsGlobalWindowInner.

  - Use-After-Free when trying to connect to a STUN server.

  - RSA Key Generation vulnerable to side-channel attack.

  - Add-On updates did not respect the same certificate trust rules as software updates.

  - Integer overflow in nsJPEGEncoder::emptyOutputBuffer.

  - DLL Hijacking due to searching %PATH% for a library.

  - WebRTC permission prompt could have been bypassed by a compromised content process.

  - Out of bound read in Date.parse().

  - Memory safety bugs fixed in Firefox 78.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct a denial-of-service, execute arbitrary code or information disclosure
  on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 78 on MacOSX.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 78
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-24/");
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

if(version_is_less(version:ffVer, test_version:"78.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"78.0", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
