###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Security Updates( mfsa_2016-01_2016-15 )-MAC OS X
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808690");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2016-1935", "CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1523");
  script_bugtraq_id(81952, 81953, 82991);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2016-09-07 12:07:55 +0530 (Wed, 07 Sep 2016)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2016-01_2016-15 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - The Buffer overflow in the BufferSubData function.

  - Multiple unspecified Vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  38.6 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 38.6");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-03/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-01/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-14/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"38.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"38.6");
  security_message(data:report);
  exit(0);
}
