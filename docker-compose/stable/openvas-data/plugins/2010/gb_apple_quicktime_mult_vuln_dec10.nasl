###############################################################################
# OpenVAS Vulnerability Test
#
# Apple QuickTime Multiple vulnerabilities - Dec10 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801680");
  script_version("2020-10-23T13:29:00+0000");
  script_tag(name:"last_modification", value:"2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_cve_id("CVE-2010-1508", "CVE-2010-0530", "CVE-2010-3800",
                "CVE-2010-3801", "CVE-2010-3802", "CVE-2010-4009");
  script_bugtraq_id(45236, 45237, 45239, 45240, 45241, 45242);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple QuickTime Multiple vulnerabilities - Dec10 (Windows)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4447");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3143");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010/dec/msg00000.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain knowledge of sensitive
  information or execute arbitrary code via a malicious video or web page.");

  script_tag(name:"affected", value:"QuickTime Player version prior to 7.6.9.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A heap overflow error when processing Track Header atoms, which could be
    exploited to execute arbitrary code via a malicious video or web page.

  - A filesystem permission error may allow a local user on a Windows system to
    access the contents of the Apple Computer directory in the user's profile.

  - A memory corruption error when handling PICT files.

  - An uninitialized memory access when processing FlashPix images.

  - A memory corruption error when processing panorama atoms in QTVR (QuickTime
    Virtual Reality) movie files.

  - An integer overflow error when processing movie files.");

  script_tag(name:"solution", value:"Upgrade to QuickTime Player version 7.6.9 or later.");

  script_tag(name:"summary", value:"The host is running QuickTime Player and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.6.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6.9", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
