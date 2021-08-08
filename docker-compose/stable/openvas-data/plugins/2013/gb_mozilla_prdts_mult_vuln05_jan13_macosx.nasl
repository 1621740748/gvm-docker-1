###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Multiple Vulnerabilities-05 January13 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803207");
  script_version("2020-08-17T08:01:28+0000");
  script_cve_id("CVE-2013-0760", "CVE-2013-0770");
  script_bugtraq_id(57199, 57207);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-17 08:01:28 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-01-16 17:04:59 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-05 January13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51752");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027955");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service
  or execute arbitrary code in the context of the browser.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 18.0 on Mac OS X");

  script_tag(name:"insight", value:"- An error within the 'CharDistributionAnalysis::HandleOneChar()' can be
    exploited to cause a buffer overflow.

  - Unspecified error in the browser engine can be exploited to corrupt memory.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 18.0 or later.");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"18.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"18.0");
  security_message(port: 0, data: report);
  exit(0);
}