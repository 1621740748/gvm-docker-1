###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Security Updates(mfsa_2018-05_2018-13)-Windows
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812892");
  script_version("2021-07-01T02:00:36+0000");
  script_cve_id("CVE-2018-5183", "CVE-2018-5184", "CVE-2018-5154", "CVE-2018-5155",
                "CVE-2018-5159", "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5170",
                "CVE-2018-5168", "CVE-2018-5174", "CVE-2018-5178", "CVE-2018-5185",
                "CVE-2018-5150");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 13:24:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-05-22 11:26:11 +0530 (Tue, 22 May 2018)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2018-05_2018-13)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to:

  - Momory corruption issues in Skia library.

  - Remote content in encrypted messages.

  - While enumerating attributes during SVG animations with clip paths.

  - While adjusting layout during SVG animations with text paths.

  - 32-bit integer use in an array without integer overflow checks in Skia
    library.

  - Crafted message headers.

  - src attribute of remote images, or links.

  - Possibility to spoof the filename of an attachment and display an arbitrary
    attachment name.

  - Manipulation of the baseURI property of the theme element.

  - Firefox incorrectly setting SEE_MASK_FLAG_NO_UI flag.

  - UTF8 to Unicode string conversion within JavaScript with extremely large
    amounts of data.

  - User submitting an embedded form.

  - Memory corruption issue in  Thunderbird 52.7.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to reads and writes invalid buffer,
  disclosure of plaintext, use-after-free vulnerability, integer overflow,
  hang on receiving the message, user opening a remote attachment which is a
  different file type than expected, allow a malicious site to install a theme
  without user interaction, allow an unknown and potentially dangerous file to
  run, buffer overflow and run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  52.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.8");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-13/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-09/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"52.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"52.8", install_path:path);
  security_message(data:report);
  exit(0);
}
