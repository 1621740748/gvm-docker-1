###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Multiple Vulnerabilities-01 Dec13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804041");
  script_version("2021-07-05T11:01:33+0000");
  script_cve_id("CVE-2013-5609", "CVE-2013-5613", "CVE-2013-5615", "CVE-2013-5616",
                "CVE-2013-5618", "CVE-2013-6671", "CVE-2013-6673");
  script_bugtraq_id(64204, 64203, 64216, 64209, 64211, 64212, 64213);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 14:42:00 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-12-23 17:09:32 +0530 (Mon, 23 Dec 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 Dec13 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 24.2 or later.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use-after-free vulnerability in the PresShell::DispatchSynthMouseMove
  function

  - JavaScript implementation does not properly enforce certain
  typeset restrictions on the generation of GetElementIC typed array stubs

  - Use-after-free vulnerability in the nsEventListenerManager::HandleEvent
  SubType function

  - unspecified error in nsGfxScrollFrameInner::IsLTR function

  - Flaw is due to the program ignoring the setting to remove the trust for
  extended validation (EV) capable root certificates");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 24.x before 24.2 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
  attacks, bypass certain security restrictions, disclose potentially sensitive
  information, and compromise a user's system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56002");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-104.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^24\." && version_in_range(version:vers, test_version:"24.0", test_version2:"24.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
