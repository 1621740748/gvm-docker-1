###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Multiple Vulnerabilities-01 August14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804735");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2014-1549", "CVE-2014-1548", "CVE-2014-1560", "CVE-2014-1559",
                "CVE-2014-1547", "CVE-2014-1558", "CVE-2014-1552", "CVE-2014-1555",
                "CVE-2014-1557", "CVE-2014-1544", "CVE-2014-1556", "CVE-2014-1550");
  script_bugtraq_id(68820, 68818, 68813, 68815, 68811, 68812, 68821,
                    68814, 68824, 68816, 68822, 68810);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2014-08-07 16:04:43 +0530 (Thu, 07 Aug 2014)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 August14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla Thunderbird and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error when buffering Web Audio for playback.

  - A use-after-free error related to ordering of control messages for Web Audio.

  - A use-after-free error when handling the FireOnStateChange event.

  - An unspecified error when using the Cesium JavaScript library to generate
  WebGL content.

  - The application bundles a vulnerable version of the Network Security
  Services (NSS) library.
and Some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version before 31.0 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 31.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59803");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-57.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"31.0"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"31.0");
  security_message(port:0, data:report);
  exit(0);
}